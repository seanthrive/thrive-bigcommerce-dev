require 'net/http'

class ApplicationController < ActionController::Base
    protect_from_forgery unless: -> { request.format.js? }

    def app_interface 

        puts "[app interface] Starting..."

        @user = current_user
        @store = current_store
        return render_error("Fuck. Can't find either the User or Store.") unless @user && @store

        @bc_api_url = bc_api_url
        @client_id = bc_client_id
        # @products = JSON.pretty_generate(@store.bc_api.products)

        puts "[app interface] API Request: Create Integrate Script Tag"

        # This is where we are putting javascript on the pages.
        # code taken from https://developer.bigcommerce.com/api-reference/storefront/content-scripts-api/scripts/createscript by selecting ruby.
        url = URI("https://api.bigcommerce.com/stores/#{@store.store_hash}/v3/content/scripts")

        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        request = Net::HTTP::Post.new(url)
        request["accept"] = 'application/json'
        request["content-type"] = 'application/json'
        request["x-auth-client"] = bc_client_id
        request["x-auth-token"] = @store.access_token # My token is wrong! gotta get that from the store.
        request.body = "{\"name\":\"Bootstrap\",
            \"description\":\"Build responsive websites\",
            \"html\":\"<script src='//integrate.thrive.today/'></script>\",
            \"auto_uninstall\":true,
            \"load_method\":\"default\",
            \"location\":\"footer\",
            \"visibility\":\"all_pages\",
            \"kind\":\"script_tag\",
            \"consent_category\":\"essential\"}"
        response = http.request(request)

        # this works but is unauthorized because I am requesting the wrong scopes. 
        # then we need to host a script somewhere, then we can post our tag and query cart. for now, bootstrap.

        puts "[app interface] Printing API response:"
        puts response.read_body

        # -----

        puts "[app interface] API Request: Create Custom Script Tag"
        url = URI("https://api.bigcommerce.com/stores/#{@store.store_hash}/v3/content/scripts")
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = true
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE

        request = Net::HTTP::Post.new(url)
        request["accept"] = 'application/json'
        request["content-type"] = 'application/json'
        request["x-auth-client"] = bc_client_id
        request["x-auth-token"] = @store.access_token # My token is wrong! gotta get that from the store.
        request.body = "{\"name\":\"Bootstrap\",
            \"description\":\"Build responsive websites\",
            \"html\":\"<script src='http://localhost:5000/tbc.js'></script>\",
            \"auto_uninstall\":true,
            \"load_method\":\"default\",
            \"location\":\"footer\",
            \"visibility\":\"all_pages\",
            \"kind\":\"script_tag\",
            \"consent_category\":\"essential\"}"
        response = http.request(request)

        puts "[app interface] Printing API response:"
        puts response.read_body

        # -----

        render :index
    end

    def serve_js
        @user = current_user
        @store = current_store

        render js: <<-bcj

var tracking_data = {
    minird_bigcommerce_cart: {},
    minird_bigcommerce_customer: {},
    minird_bigcommerce_last_order: {},
    minird_bigcommerce_all_orders: {}
};

var cart_promise = function () {
    return new Promise((resolve, reject) => {
        window.stencilUtils.api.cart.getCart({}, (err, response) => {
            console.log('B) CART id', response.id);

            var num_items = Object.values(response.lineItems).reduce((total, itemTypeArray) => {
                return total + itemTypeArray.length;
            }, 0);

            tracking_data.minird_bigcommerce_cart.cart_amount = response.cartAmount;
            tracking_data.minird_bigcommerce_cart.base_amount = response.baseAmount;
            tracking_data.minird_bigcommerce_cart.discount_amount = response.discountAmount;
            tracking_data.minird_bigcommerce_cart.line_items_length = num_items;

            resolve();
        });
    });
};

var customer_promise = function () {
    return new Promise((resolve, reject) => {
        // Customer JWT API Request
        var xmlhttp = new XMLHttpRequest();
        xmlhttp.onreadystatechange = function () {
            if (xmlhttp.readyState == 4) {
                if (xmlhttp.status == 200) {
                    var decoded = atob(xmlhttp.responseText.split('.')[1]);
                    var jsonData = JSON.parse(decoded);
                    var user_id = jsonData.customer.id;
                    console.log('C) CUSTOMER', user_id);
                    tracking_data.minird_bigcommerce_customer.bool_id = user_id;
                    resolve(user_id);
                } else if (xmlhttp.status == 404) {
                    console.log('C) CUSTOMER', 'Not logged in!');
                } else {
                    console.log('C) CUSTOMER', 'Something went wrong!');
                }
            }
        }
        xmlhttp.open("GET", "https://thrive-sandbox.mybigcommerce.com/customer/current.jwt?app_client_id=#{bc_client_id}", true);
        xmlhttp.send();
    });
};

var gather_promise = function (user_id) {
    return new Promise((resolve, reject) => {
        // Gather data request to backend server.
        var gather_req = new XMLHttpRequest();
        gather_req.addEventListener("readystatechange", function () {
            if (this.readyState === this.DONE) {
                var gather_response = JSON.parse(this.responseText);

                // All orders:
                tracking_data.minird_bigcommerce_all_orders.size = gather_response.length;
                tracking_data.minird_bigcommerce_all_orders.sum_total_inc_tax = gather_response.reduce((total, curr) => {
                    return total + curr.total_inc_tax;
                }, 0);

                // Most recent order
                // Determine "most recent" by date_created or id. 
                var most_recent_order = gather_response.sort((a, b) => {
                    return a - b;
                })[0];
                tracking_data.minird_bigcommerce_last_order.total_inc_tax = most_recent_order.total_inc_tax;
                tracking_data.minird_bigcommerce_last_order.discount_amount = most_recent_order.discount_amount;
                tracking_data.minird_bigcommerce_last_order.created_at = most_recent_order.date_created;
                
                console.log("D)", tracking_data);
            }
        });
        var gather_req_url = "#{host_url}/gather?sh=#{@store.store_hash}&at=#{@store.access_token}&cid=" + user_id;
        gather_req.open("GET", gather_req_url);
        gather_req.send();
    });
};

new Promise((resolve, reject) => {
    console.log('A) initial promise');
    resolve();
})
.then(() => cart_promise())
.then(() => customer_promise())
.then((user_id) => gather_promise(user_id));

        bcj
    end

    def gather_info 
        # @user = current_user
        # @store = current_store

        @storeHash = params[:sh]
        @accessToken = params[:at]
        @customer_id = params[:cid]

        orders_url = URI.parse("https://api.bigcommerce.com/stores/#{@storeHash}/v2/orders?customer_id=#{@customer_id}")
        orders_req = Net::HTTP::Get.new(orders_url.to_s)
        orders_req['x-auth-token'] = "#{@accessToken}"
        orders_req['accept'] = "application/json"
        orders_req['Content-Type'] = "application/json"
        orders_res = Net::HTTP.start(orders_url.host, orders_url.port, :use_ssl => orders_url.scheme == 'https') {|http|
            http.request(orders_req)
        } 
        render json: orders_res.body

        # GET https://api.bigcommerce.com/stores/#{@storeHash}/v3/orders 
        # sum of order_total_inc_tax, num of orders, most recent total_inc_tax, most recent

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
        render plain: "Uninstall App Route"
    end

    def remove_user
        render plain: "Remove User Route"
    end

    private 

    # Gets the current user from session
    def current_user
        return nil unless session[:user_id]
        User.find(session[:user_id])
    end
    
    # Gets the current user's store from session
    def current_store
        user = current_user
        return nil unless user
        return nil unless session[:store_id]
        user.stores.find(session[:store_id])
    end

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

    # Get Host URL from env
    def host_url 
        ENV['HOST_URL']
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

    def bc_access_token
        ENV['BC_ACCESS_TOKEN']
    end
    
    # The scopes we are requesting (must match what is requested in
    # Developer Portal).
    def scopes
        ENV.fetch('SCOPES', 'store_v2_products store_content_checkout store_v2_content')
    end
end
