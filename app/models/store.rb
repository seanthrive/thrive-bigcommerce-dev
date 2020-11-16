class Store < ApplicationRecord
    has_and_belongs_to_many :users

    def bc_api
        config = {
            store_hash: self.store_hash,
            client_id: bc_client_id,
            access_token: self.access_token
        }
        return Bigcommerce::Api.new(config)
    end

    private

    # Get client id from env
    def bc_client_id
        ENV['BC_CLIENT_ID']
    end
end
