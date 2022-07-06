class CreateUsers < ActiveRecord::Migration[5.2]
  def change
    create_table :users do |t|
      t.string :username, presence: true

      t.timestamps
    end
  end
end
