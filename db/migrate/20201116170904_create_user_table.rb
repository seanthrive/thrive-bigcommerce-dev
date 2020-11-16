class CreateUserTable < ActiveRecord::Migration[6.0]
  def change

    create_table :users do |t|
      t.string :email
      t.timestamps
    end

    change_table :stores do |t|
      t.remove :username, :email
      t.integer :admin_user_id
    end

    create_join_table :stores, :users do |t|
      t.belongs_to :stores
      t.belongs_to :users
    end

  end
end
