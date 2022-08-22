class HomeController < ApplicationController
  def index
    @identities = Identity.all
  end
end
