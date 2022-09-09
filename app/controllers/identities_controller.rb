class IdentitiesController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
    identity = Identity.create(uid: params[:uid])
    challenge = Base64.strict_encode64(SecureRandom.random_bytes(32))
    session[identity.id] = challenge
    render json: {
      identity: identity,
      challenge: challenge
    }
  end

  def update
    identity = Identity.find(params[:id])

    client_data = JSON.parse(Base64.urlsafe_decode64(params[:identity][:client_data]))
    attestation_object = CBOR.decode(Base64.urlsafe_decode64(params[:identity][:attestation_object]))
    auth_data = attestation_object['authData']
    id_len_bytes = auth_data[53, 2].unpack1("H*").to_i(16)
    credential_id = auth_data[55, id_len_bytes]
    public_key_bytes = auth_data[55 + id_len_bytes, auth_data.length - 55 - id_len_bytes]
    CBOR.decode(public_key_bytes)

    if session[identity.id] == client_data[:challenge]
      identity.update(
        data: {
          credential_id: Base64.strict_encode64(credential_id),
          public_key: Base64.strict_encode64(public_key_bytes)
        }
      )
      render json: { identity: identity }
    else
      render json: { error: 'challenge does not match' }, status: 400
    end
  end

  def initiate
    identity = Identity.find(params[:id])
    challenge = Base64.strict_encode64(SecureRandom.random_bytes(32))
    session[identity.id] = challenge

    render json: {
      identity: {
        id: identity.id,
        credential_id: identity.data['credential_id']
      },
      challenge: challenge
    }
  end

  def verify
    identity = Identity.find(params[:id])
    user_handle = Base64.urlsafe_decode64(params['user_handle']).to_i

    if identity && identity.id == user_handle
      client_data = JSON.parse(Base64.urlsafe_decode64(params['client_data']));

      if session[identity.id] == Base64.urlsafe_decode64(client_data['challenge'])
        uri = URI.parse(client_data['origin'])

        if uri.scheme == request.scheme && uri.host == request.host
          auth_data = Base64.urlsafe_decode64(params['authentication_data'])
          pointer = 0

          rp_id_hash = auth_data[pointer, 32]
          pointer += 32
          flags_bytes = auth_data[pointer, 1].ord
          pointer += 1
          sign_count = auth_data[pointer, 4]
          pointer += 4

          flags = AuthenticationFlags.new(flags_bytes)
          authenticator_data = AuthenticatorData.new(rp_id_hash, flags, sign_count)

          if flags.at
            aaguid = auth_data[pointer, 16]
            pointer += 16

            credential_id_len = auth_data[pointer, 2].unpack1("H*").to_i(16)
            pointer += 2
            credential_id = auth_data[pointer, credential_id_len]
            pointer += credential_id_len

            #credential_public_key = CBOR.decode()
          end

          if flags.ed
            #extension_object =
          end

          if pointer > auth_data.size
            raise 'invalid auth data'
          end

          expected_rp_id_hash = Digest::SHA256.digest('3c68383c-9a7a-407b-b696-af3420821dca')

          if authenticator_data.rp_id_hash != expected_rp_id_hash
            raise 'invalid rp id'
          end

          if !authenticator_data.flags.up
            raise 'user is not present'
          end

          if !authenticator_data.flags.uv
            raise 'user is not verified'
          end
        end
      end
    end
  end

  class AuthenticationFlags
    def initialize(flags_bytes)
      @flags_bytes = flags_bytes
    end

    def up
      flags_bytes & (1 << 0) != 0
    end

    def uv
      flags_bytes & (1 << 2) != 0
    end

    def be
      flags_bytes & (1 << 3) != 0
    end

    def bs
      flags_bytes & (1 << 4) != 0
    end

    def at
      flags_bytes & (1 << 6) != 0
    end

    def ed
      flags_bytes & (1 << 7) != 0
    end

    private

      attr_reader :flags_bytes
  end

  class AuthenticatorData
    attr_reader :rp_id_hash, :flags

    def initialize(rp_id_hash, flags, sign_count)
      @rp_id_hash = rp_id_hash
      @flags = flags
      @sign_count = sign_count
    end

    def sign_count
      sign_count.unpack1("H*").to_i(16)
    end
  end
end
