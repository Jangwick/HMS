-- LOG1 Implementation Migration
-- Date: 2026-03-13

CREATE TABLE IF NOT EXISTS material_requests (
    id BIGSERIAL PRIMARY KEY,
    request_no TEXT UNIQUE NOT NULL,
    project_id BIGINT NULL,
    requesting_department_id BIGINT,
    requested_by BIGINT,
    item_id BIGINT,
    requested_item_name TEXT,
    storage_location_id BIGINT,
    quantity NUMERIC(12,2) NOT NULL DEFAULT 0,
    recipient_name TEXT,
    recipient_lang TEXT,
    allocation_strategy TEXT DEFAULT 'FEFO',
    suggested_batch_id BIGINT,
    suggested_batch_number TEXT,
    suggestion_notes TEXT,
    validated_by BIGINT,
    validated_at TIMESTAMPTZ,
    dispensed_batch_id BIGINT,
    dispensed_batch_number TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    rejection_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Backward-safe column add for already existing tables
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS requested_item_name TEXT;
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS allocation_strategy TEXT DEFAULT 'FEFO';
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS suggested_batch_id BIGINT;
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS suggested_batch_number TEXT;
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS suggestion_notes TEXT;
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS validated_by BIGINT;
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS validated_at TIMESTAMPTZ;
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS dispensed_batch_id BIGINT;
ALTER TABLE material_requests ADD COLUMN IF NOT EXISTS dispensed_batch_number TEXT;

-- Optional inventory fields for stronger FIFO/FEFO support
ALTER TABLE inventory ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ DEFAULT NOW();
ALTER TABLE inventory ADD COLUMN IF NOT EXISTS batch_number TEXT;
ALTER TABLE inventory ADD COLUMN IF NOT EXISTS expiry_date DATE;

CREATE INDEX IF NOT EXISTS idx_inventory_item_name ON inventory(item_name);
CREATE INDEX IF NOT EXISTS idx_inventory_batch_number ON inventory(batch_number);
CREATE INDEX IF NOT EXISTS idx_inventory_expiry_date ON inventory(expiry_date);

CREATE TABLE IF NOT EXISTS discrepancy_reports (
    id BIGSERIAL PRIMARY KEY,
    report_no TEXT UNIQUE NOT NULL,
    receiving_id BIGINT,
    supplier_id BIGINT,
    issue_type TEXT NOT NULL,
    expected_qty NUMERIC(12,2),
    received_qty NUMERIC(12,2),
    discrepancy_qty NUMERIC(12,2),
    remarks TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    created_by BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS supplier_notifications (
    id BIGSERIAL PRIMARY KEY,
    discrepancy_report_id BIGINT,
    supplier_id BIGINT,
    channel TEXT,
    subject TEXT,
    message TEXT,
    status TEXT NOT NULL DEFAULT 'SENT',
    sent_by BIGINT,
    sent_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS procurement_budget_approvals (
    id BIGSERIAL PRIMARY KEY,
    requisition_id BIGINT NOT NULL,
    requested_amount NUMERIC(14,2) NOT NULL DEFAULT 0,
    approved_amount NUMERIC(14,2),
    status TEXT NOT NULL DEFAULT 'PENDING_FINANCE',
    finance_remarks TEXT,
    requested_by BIGINT,
    approved_by BIGINT,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS project_material_tracking (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL,
    material_request_id BIGINT,
    stage TEXT NOT NULL,
    status TEXT NOT NULL,
    notes TEXT,
    updated_by BIGINT,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS supplier_documents (
    id BIGSERIAL PRIMARY KEY,
    doc_type TEXT NOT NULL,
    document_no TEXT,
    supplier_id BIGINT,
    requisition_id BIGINT,
    receiving_id BIGINT,
    file_path TEXT,
    metadata JSONB,
    captured_via TEXT NOT NULL DEFAULT 'UPLOAD',
    created_by BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Optional procurement table extension for finance gate visibility
ALTER TABLE purchase_orders
    ADD COLUMN IF NOT EXISTS finance_approval_status TEXT DEFAULT 'PENDING_FINANCE';

ALTER TABLE purchase_orders
    ADD COLUMN IF NOT EXISTS finance_requested_at TIMESTAMPTZ;
