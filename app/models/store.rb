class Store < ApplicationRecord
    # has_many :users, :through => :store_users
    has_and_belongs_to_many :users
end
