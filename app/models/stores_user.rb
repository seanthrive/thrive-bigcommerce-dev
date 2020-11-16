class StoresUser < ApplicationRecord
    belongs_to :stores
    belongs_to :users
end
