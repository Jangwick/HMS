-- ============================================================================
-- FIX RLS POLICIES FOR CT3 HADS TABLES
-- ============================================================================
-- Run this to fix the row-level security policies that are blocking inserts
-- Option 1: Create permissive policies
-- Option 2: Disable RLS (commented out - use only if Option 1 fails)
-- ============================================================================

-- Drop all existing policies for these tables
DROP POLICY IF EXISTS "Users can manage transfers" ON patient_transfers;
DROP POLICY IF EXISTS "Users can insert transfers" ON patient_transfers;
DROP POLICY IF EXISTS "Users can update transfers" ON patient_transfers;
DROP POLICY IF EXISTS "Users can delete transfers" ON patient_transfers;
DROP POLICY IF EXISTS "Users can view transfers" ON patient_transfers;

DROP POLICY IF EXISTS "Users can manage discharge plans" ON discharge_plans;
DROP POLICY IF EXISTS "Users can insert discharge plans" ON discharge_plans;
DROP POLICY IF EXISTS "Users can update discharge plans" ON discharge_plans;
DROP POLICY IF EXISTS "Users can delete discharge plans" ON discharge_plans;
DROP POLICY IF EXISTS "Users can view discharge plans" ON discharge_plans;

DROP POLICY IF EXISTS "Users can manage documents" ON patient_documents;
DROP POLICY IF EXISTS "Users can insert documents" ON patient_documents;
DROP POLICY IF EXISTS "Users can update documents" ON patient_documents;
DROP POLICY IF EXISTS "Users can delete documents" ON patient_documents;
DROP POLICY IF EXISTS "Users can view documents" ON patient_documents;

DROP POLICY IF EXISTS "Users can manage line items" ON billing_line_items;
DROP POLICY IF EXISTS "Users can insert line items" ON billing_line_items;
DROP POLICY IF EXISTS "Users can update line items" ON billing_line_items;
DROP POLICY IF EXISTS "Users can delete line items" ON billing_line_items;
DROP POLICY IF EXISTS "Users can view line items" ON billing_line_items;

-- ============================================================================
-- OPTION 1: Create permissive policies (works with any authenticated user)
-- ============================================================================

-- patient_transfers policies (allow all operations)
CREATE POLICY "Allow all for patient_transfers" ON patient_transfers 
    FOR ALL 
    USING (true) 
    WITH CHECK (true);

-- discharge_plans policies (allow all operations)
CREATE POLICY "Allow all for discharge_plans" ON discharge_plans 
    FOR ALL 
    USING (true) 
    WITH CHECK (true);

-- patient_documents policies (allow all operations)
CREATE POLICY "Allow all for patient_documents" ON patient_documents 
    FOR ALL 
    USING (true) 
    WITH CHECK (true);

-- billing_line_items policies (allow all operations)
CREATE POLICY "Allow all for billing_line_items" ON billing_line_items 
    FOR ALL 
    USING (true) 
    WITH CHECK (true);

-- ============================================================================
-- OPTION 2: Disable RLS entirely (UNCOMMENT IF OPTION 1 FAILS)
-- ============================================================================
-- WARNING: This removes all row-level security. Only use in development.
-- 
-- ALTER TABLE patient_transfers DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE discharge_plans DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE patient_documents DISABLE ROW LEVEL SECURITY;
-- ALTER TABLE billing_line_items DISABLE ROW LEVEL SECURITY;

-- ============================================================================
-- VERIFICATION
-- ============================================================================
-- Check that policies were created successfully
SELECT schemaname, tablename, policyname, cmd 
FROM pg_policies 
WHERE tablename IN ('patient_transfers', 'discharge_plans', 'patient_documents', 'billing_line_items')
ORDER BY tablename, cmd;
