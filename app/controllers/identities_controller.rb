class IdentitiesController < ApplicationController
  skip_before_action :verify_authenticity_token

  def create
    identity = Identity.create(uid: params[:uid])
    challenge = Base64.strict_encode64(SecureRandom.random_bytes(32))
    render json: {
      identity: identity,
      challenge: challenge
    }
  end
end
