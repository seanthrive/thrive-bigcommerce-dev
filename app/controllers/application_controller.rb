class ApplicationController < ActionController::Base
    def app_interface 
        render plain: "App Interface Route"
    end

    def load
        puts "[load] Loading..."

        # Decode payload
        payload = parse_signed_payload
        return render_error('[load] Invalid payload signature!') unless payload

        email = payload[:user][:email]
        store_hash = payload[:store_hash]

        # Lookup store
        store = Store.find_by store_hash: store_hash
        return render_error("[load] Store not found!") unless store

        # Find/create user
        user = User.first_or_create(email: email)
        return render_error('[load] User not found!') unless user

        # Add store association if it doesn't exist
        unless StoresUser.find_by(store_id: store.id, user_id: user.id)
          user.stores << store
          user.save
        end

        # Login and redirect to home page
        logger.info "[load] Loading app for user '#{email}' on store '#{store_hash}'"
        session[:store_id] = store.id
        session[:user_id] = user.id
        redirect_to '/'
    end

    def uninstall
        render plain: "Uninstall Route"
    end

    def remove_user
        render plain: "Remove User Route"
    end

    private 

    # Verify given signed_payload string and return the data if valid.
    def parse_signed_payload
        signed_payload = params[:signed_payload]
        message_parts = signed_payload.split('.')
        
        encoded_json_payload = message_parts[0]
        encoded_hmac_signature = message_parts[1]
        
        payload = Base64.decode64(encoded_json_payload)
        provided_signature = Base64.decode64(encoded_hmac_signature)
        
        expected_signature = sign_payload(bc_client_secret, payload)
        
        if secure_compare(expected_signature, provided_signature)
            return JSON.parse(payload, symbolize_names: true)
        end
        
        nil
    end

    # Sign payload string using HMAC-SHA256 with given secret
    def sign_payload(secret, payload)
        OpenSSL::HMAC::hexdigest('sha256', secret, payload)
    end

    # Time consistent string comparison. Most library implementations
    # will fail fast allowing timing attacks.
    def secure_compare(a, b)
        return false if a.blank? || b.blank? || a.bytesize != b.bytesize
        l = a.unpack "C#{a.bytesize}"
    
        res = 0
        b.each_byte { |byte| res |= byte ^ l.shift }
        res == 0
    end
    
    def render_error(e)
        logger.warn "ERROR: #{e}"
        @error = e
        erb :error
    end
    
    # Get client id from env
    def bc_client_id
        ENV['BC_CLIENT_ID']
    end
    
    # Get client secret from env
    def bc_client_secret
        ENV['BC_CLIENT_SECRET']
    end
    
    # Get the API url from env
    def bc_api_url
        ENV['BC_API_ENDPOINT'] || 'https://api.bigcommerce.com'
    end
    
    # Full url to this app
    def app_url
        ENV['APP_URL']
    end
    
    # The scopes we are requesting (must match what is requested in
    # Developer Portal).
    def scopes
        ENV.fetch('SCOPES', 'store_v2_products store_content_checkout store_v2_content')
    end
end
