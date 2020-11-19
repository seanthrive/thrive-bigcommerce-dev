class OmniauthsController < ApplicationController
  def callback

    auth = request.env['omniauth.auth']
    unless auth && auth[:extra][:raw_info][:context]
      return render_error("[install] Invalid credentials: #{JSON.pretty_generate(auth[:extra])}")
    end

    puts "[auth callback] Installing..."

    email = auth[:info][:email]
    store_hash = auth[:extra][:context].split('/')[1]
    token = auth[:credentials][:token].token
    scope = auth[:extra][:scopes]

    # Lookup store
    store = Store.find_by store_hash: store_hash

    if store
      # Update store record
      puts "[auth callback] Updating token for store '#{store_hash}' with scope '#{scope}'"
      store.update(access_token: token, scope: scope)
      user = User.find(store.admin_user_id)
    else
      # Create store record
      puts "[auth callback] Installing app for store '#{store_hash}' and scope '#{scope}"
      store = Store.create(store_hash: store_hash, access_token: token, scope: scope)

      # Create admin user and associate with store
      user = User.first_or_create(email: email)
      user.stores << store
      user.save

      # Set admin user in Store record
      store.admin_user_id = user.id
      store.save
    end

    # Other one-time installation provisioning goes here.

    # Login and redirect to home page
    session[:store_id] = store.id
    session[:user_id] = user.id

    redirect_to '/'
  end

  private 

  def render_error(e)
      logger.warn "ERROR: #{e}"
      @error = e
      erb :error
  end
end
