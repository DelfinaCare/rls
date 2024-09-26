DO $$
DECLARE
    r RECORD;
BEGIN
    FOR r IN
        SELECT policyname
        FROM pg_policies
        WHERE tablename = 'items'
    LOOP
        EXECUTE 'DROP POLICY ' || quote_ident(r.policyname) || ' ON items';
    END LOOP;
END $$;
