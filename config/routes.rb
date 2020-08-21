Rails.application.routes.draw do
  resources :stores
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html
  get '/auth/:name/callback' => 'omniauths#callback'
  get '/load' => 'omniauths#load'
  get '/uninstall' => 'omniauths#uninstall'
  root 'welcome#index'
end
