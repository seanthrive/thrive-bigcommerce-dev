class User < ApplicationRecord
    # has_many :stores, :through => :store_users
    has_and_belongs_to_many :stores
end
