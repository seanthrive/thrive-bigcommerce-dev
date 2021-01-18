Rails.application.routes.draw do
  resources :stores
  
  get '/auth/:name/callback' => 'omniauths#callback'

  root 'application#app_interface'
  get '/load' => 'application#load'
  get '/uninstall' => 'application#uninstall'
  get '/remove' => 'application#remove_user'
  
  get '/tbc' => 'application#serve_js', xhr: true, format: :js
  get '/gather' => 'application#gather_info', xhr: true
end
