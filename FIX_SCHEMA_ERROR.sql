-- SQL Patch to fix missing full_name column and other potential schema issues
-- Run these commands in your Supabase SQL Editor (Dashboard > SQL Editor > New Query)

-- 1. Ensure the full_name column exists in the users table
ALTER TABLE users ADD COLUMN IF NOT EXISTS full_name VARCHAR(100);

-- 2. Populate full_name from username for existing records if it's empty
UPDATE users SET full_name = username WHERE full_name IS NULL OR full_name = '';

-- 3. If you just added the column and still see cache errors, 
-- you might need to reload the PostgREST schema cache.
-- In the Supabase Dashboard, go to Settings -> API and look for 
-- "PostgREST config" or simply wait a few minutes for the cache to refresh.

-- Verify the column exists
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'users' AND column_name = 'full_name';
