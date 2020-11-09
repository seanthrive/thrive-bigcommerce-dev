class OmniauthsController < ApplicationController
  def callback

    puts "------------ IN AUTH/:NAME/CALLBACK"

    auth = request.env['omniauth.auth']
    unless auth && auth[:extra][:raw_info][:context]
      return render_error("[install] Invalid credentials: #{JSON.pretty_generate(auth[:extra])}")
    end

    email = auth[:info][:email]
    store_hash = auth[:extra][:context].split('/')[1]
    token = auth[:credentials][:token].token
    scope = auth[:extra][:scopes]

    # TODO: Find and/or create store and admin user.

    redirect_to '/'
  end

  def load
    render plain: "This is the load route"
  end

  def uninstall
  end
end
