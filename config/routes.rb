Rails.application.routes.draw do
  resources :identities do
    member do
      post :initiate
      post :verify
    end
  end
  get 'home/index'
end
