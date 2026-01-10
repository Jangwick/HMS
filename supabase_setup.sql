-- =====================================================
-- Supabase Database Setup Script for HMS
-- Hospital Management System
-- =====================================================
-- Run this script in Supabase SQL Editor to create the users table
-- Go to: Supabase Dashboard > SQL Editor > New Query
-- =====================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =====================================================
-- SINGLE USERS TABLE FOR ALL SUBSYSTEMS
-- =====================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) NOT NULL,
    email VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    subsystem VARCHAR(20) NOT NULL,  -- hr1, hr2, ct1, ct2, log1, fin1, etc.
    department VARCHAR(50) NOT NULL,  -- HR, CORE_TRANSACTION, LOGISTICS, FINANCIALS
    role VARCHAR(50) DEFAULT 'Staff',
    password_created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    password_expires_at TIMESTAMP NOT NULL DEFAULT (NOW() + INTERVAL '90 days'),
    password_history JSONB DEFAULT '[]'::jsonb,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE,
    status VARCHAR(20) DEFAULT 'Pending', -- Pending, Active, Rejected
    
    -- Unique constraint: username must be unique within each subsystem
    CONSTRAINT unique_username_per_subsystem UNIQUE (username, subsystem),
    -- Unique constraint: email must be unique within each subsystem
    CONSTRAINT unique_email_per_subsystem UNIQUE (email, subsystem)
);

-- =====================================================
-- INDEXES FOR PERFORMANCE
-- =====================================================

-- Index for username lookups (most common query)
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- Index for subsystem filtering
CREATE INDEX IF NOT EXISTS idx_users_subsystem ON users(subsystem);

-- Composite index for login queries
CREATE INDEX IF NOT EXISTS idx_users_username_subsystem ON users(username, subsystem);

-- Index for email lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Index for active users
CREATE INDEX IF NOT EXISTS idx_users_is_active ON users(is_active) WHERE is_active = TRUE;

-- Index for user status
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);

-- =====================================================
-- ROW LEVEL SECURITY (Recommended for production)
-- =====================================================

-- Enable Row Level Security
-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Example policy: Users can only see their own record
-- CREATE POLICY "Users can view own data" ON users
--     FOR SELECT USING (auth.uid()::text = id::text);

-- =====================================================
-- SETUP COMPLETE
-- =====================================================
-- After running this script:
-- 1. Get SUPABASE_URL and SUPABASE_KEY from: Settings > API
-- 2. Add these to your .env file
-- 3. Run: python init_db.py to create default admin users
-- =====================================================
