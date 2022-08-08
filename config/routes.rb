Rails.application.routes.draw do
  resources :identities
  get 'home/index'
end
