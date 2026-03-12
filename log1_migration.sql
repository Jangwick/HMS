-- LOG1 Implementation Migration
-- Date: 2026-03-13

CREATE TABLE IF NOT EXISTS material_requests (
    id BIGSERIAL PRIMARY KEY,
    request_no TEXT UNIQUE NOT NULL,
    project_id BIGINT NULL,
    requesting_department_id BIGINT,
    requested_by BIGINT,
    item_id BIGINT,
    storage_location_id BIGINT,
    quantity NUMERIC(12,2) NOT NULL DEFAULT 0,
    recipient_name TEXT,
    recipient_lang TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    rejection_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

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
