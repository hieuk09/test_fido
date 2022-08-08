class CreateIdentities < ActiveRecord::Migration[7.0]
  def change
    create_table :identities do |t|
      t.string :uid
      t.jsonb :data

      t.timestamps
    end
  end
end
