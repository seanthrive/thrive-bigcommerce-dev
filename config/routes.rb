Rails.application.routes.draw do
  resources :stores
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html
  get '/auth/:name/callback' => 'omniauths#callback'

  root 'application#app_interface'
  get '/load' => 'application#load'
  get '/uninstall' => 'application#uninstall'
  get '/remove' => 'application#remove_user'
end
