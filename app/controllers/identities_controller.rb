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
      render json: { error: 'challenge does not match' }
    end
  end

  def show
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
end
