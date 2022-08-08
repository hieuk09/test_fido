class IdentitiesController < ApplicationController
  def create
    identity = Identity.create(uid: params[:uid])
    render json: identity.as_json
  end
end
