DO $$
DECLARE
    policy_name TEXT;
BEGIN
    FOR policy_name IN
        SELECT policyname
        FROM pg_policies
        WHERE tablename = 'items'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON items;', policy_name);
    END LOOP;
END $$;

delete from alembic_version;

---------------------------------------------------------------

-- Insert user 1
INSERT INTO users (username) VALUES ('user1');

-- Insert user 2
INSERT INTO users (username) VALUES ('user2');


-- Insert items for user 1 (id of user1 is assumed to be 1)
INSERT INTO items (title, description, owner_id) VALUES
('Item 1 for User 1', 'Description of item 1 for user 1', 1),
('Item 2 for User 1', 'Description of item 2 for user 1', 1);

-- Insert items for user 2 (id of user2 is assumed to be 2)
INSERT INTO items (title, description, owner_id) VALUES
('Item 1 for User 2', 'Description of item 1 for user 2', 2),
('Item 2 for User 2', 'Description of item 2 for user 2', 2);


---------------------------------------------------------------

-- Enable Row-Level Security on the table
ALTER TABLE items ENABLE ROW LEVEL SECURITY;

-- Create the RLS policy
CREATE POLICY multi_cmd_policy
ON items
FOR SELECT, INSERT
USING (owner_id > 2)
WITH CHECK (owner_id > 2);
