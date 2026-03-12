# LOG1 — Inventory, Procurement, and Project Materials: Implementation Plan

**Prepared:** March 13, 2026  
**Subsystem:** LOG1  
**Scope:** Inventory receiving, discrepancy handling, inter-department requests, warehouse-to-procurement escalation, project material lifecycle tracking, and document auto-recording (PO/DR).

---

## 1. Requested Changes (As-Is → To-Be)

## 1.1 Item Selection and Request Input
- **As-Is:** Item handling is not enforcing item + storage location selection with complete request metadata.
- **To-Be:** Request/issue form must include:
  - Item name (from master items)
  - Storage location (warehouse/bin/location)
  - Quantity
  - Recipient (requesting department/person)
  - Recipient note/label (`recipient_lang` if this is an existing field; otherwise normalize to `recipient_name`)

## 1.2 Procurement Budget Approval from Finance
- **As-Is:** Procurement can impact finance budget automatically.
- **To-Be:** No automatic deduction on finance budget. Every procurement budget consumption requires explicit **Finance Approval** step.

## 1.3 Discrepancy Report + Notify Supplier
- **As-Is:** Receiving issues (wrong/short items) are not escalated immediately via formal workflow.
- **To-Be:** On receiving, user can:
  - Create Discrepancy Report
  - Notify Supplier
  - Track supplier correction status until resolved

## 1.4 Receiving Requests from Other Departments
- **As-Is:** Inbound requests from departments are not consistently routed into warehouse workflow.
- **To-Be:** Department material requests are received, queued, evaluated by stock availability, and responded to with fulfillment/rejection status.

## 1.5 Notify Requestor if Out of Stock
- **As-Is:** Rejections are not guaranteed to notify requestor.
- **To-Be:** If stock is insufficient, request is rejected with reason `Out of Stock` and requestor gets immediate notification.

## 1.6 Warehouse → Procurement Escalation
- **As-Is:** Missing stock may stop at warehouse level.
- **To-Be:** If warehouse has no stock for project request, warehouse auto-creates Purchase Requisition routed to Procurement and awaits Finance budget approval.

## 1.7 Real-Time Project Tracking
- **As-Is:** Project material flow statuses are fragmented.
- **To-Be:** End-to-end project tracking statuses:
  - Request Project Materials
  - Delivering Materials
  - Project Status (In Progress / Completed)
  - Budget approval from Finance where required

## 1.8 PO/DR Auto Recording
- **As-Is:** Supplier PO/DR documents may be manually filed only.
- **To-Be:** Supplier documents (PO, DR) are automatically recorded and linked to procurement/receiving transactions.

---

## 2. Target Workflow (To-Be)

1. Department creates material request (item + location + qty + recipient info).  
2. Warehouse checks on-hand stock by location.  
3. If stock available:
   - Reserve stock
   - Start delivery (`Delivering Materials`)
   - Complete issue and update project material ledger.
4. If stock unavailable:
   - Reject request as `Out of Stock`
   - Notify requestor immediately
   - Create purchase requisition for Procurement.
5. Procurement prepares sourcing and submits budget request to Finance.  
6. Finance approves/rejects budget (**no auto deduction before approval**).  
7. Supplier delivery received by warehouse.  
8. Receiver validates received qty/spec:
   - If correct: post receiving and update stock.
   - If discrepancy: create discrepancy report and notify supplier.
9. Supplier sends correction/replacement; discrepancy is resolved and closed.  
10. PO/DR files are auto-recorded and attached to the transaction.  
11. Project status transitions: `In Progress` → `Completed`.

---

## 3. Data Model Changes

## 3.1 New Tables

```sql
CREATE TABLE material_requests (
    id BIGSERIAL PRIMARY KEY,
    request_no TEXT UNIQUE NOT NULL,
    project_id BIGINT NULL,
    requesting_department_id BIGINT NOT NULL,
    requested_by BIGINT NOT NULL,
    item_id BIGINT NOT NULL,
    storage_location_id BIGINT NOT NULL,
    quantity NUMERIC(12,2) NOT NULL CHECK (quantity > 0),
    recipient_name TEXT,
    recipient_lang TEXT,
    status TEXT NOT NULL DEFAULT 'PENDING',
    -- PENDING | APPROVED | REJECTED_OUT_OF_STOCK | FOR_DELIVERY | DELIVERED | CANCELLED
    rejection_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE discrepancy_reports (
    id BIGSERIAL PRIMARY KEY,
    report_no TEXT UNIQUE NOT NULL,
    receiving_id BIGINT NOT NULL,
    supplier_id BIGINT NOT NULL,
    issue_type TEXT NOT NULL,
    -- SHORT_DELIVERY | WRONG_ITEM | DAMAGED | EXPIRED | OTHER
    expected_qty NUMERIC(12,2),
    received_qty NUMERIC(12,2),
    discrepancy_qty NUMERIC(12,2),
    remarks TEXT,
    status TEXT NOT NULL DEFAULT 'OPEN',
    -- OPEN | SUPPLIER_NOTIFIED | UNDER_CORRECTION | RESOLVED | CLOSED
    created_by BIGINT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE supplier_notifications (
    id BIGSERIAL PRIMARY KEY,
    discrepancy_report_id BIGINT NOT NULL,
    supplier_id BIGINT NOT NULL,
    channel TEXT NOT NULL,
    -- EMAIL | SMS | PORTAL | PHONE_LOG
    subject TEXT,
    message TEXT,
    status TEXT NOT NULL DEFAULT 'SENT',
    sent_by BIGINT NOT NULL,
    sent_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE procurement_budget_approvals (
    id BIGSERIAL PRIMARY KEY,
    requisition_id BIGINT NOT NULL,
    requested_amount NUMERIC(14,2) NOT NULL,
    approved_amount NUMERIC(14,2),
    status TEXT NOT NULL DEFAULT 'PENDING_FINANCE',
    -- PENDING_FINANCE | APPROVED | REJECTED
    finance_remarks TEXT,
    requested_by BIGINT NOT NULL,
    approved_by BIGINT,
    requested_at TIMESTAMPTZ DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE project_material_tracking (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL,
    material_request_id BIGINT,
    stage TEXT NOT NULL,
    -- REQUEST_PROJECT_MATERIALS | DELIVERING_MATERIALS | MATERIALS_DELIVERED
    status TEXT NOT NULL,
    -- IN_PROGRESS | COMPLETED | BLOCKED
    notes TEXT,
    updated_by BIGINT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE supplier_documents (
    id BIGSERIAL PRIMARY KEY,
    doc_type TEXT NOT NULL,
    -- PO | DR
    document_no TEXT,
    supplier_id BIGINT,
    requisition_id BIGINT,
    receiving_id BIGINT,
    file_path TEXT,
    metadata JSONB,
    captured_via TEXT NOT NULL DEFAULT 'UPLOAD',
    -- UPLOAD | AUTO_LINK | API
    created_by BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

## 3.2 Existing Table Updates
- Add `storage_location_id` to relevant line-item/request tables if missing.
- Add finance approval reference in purchase requisition table (`budget_approval_id`).
- Ensure receiving transaction table has `supplier_id`, `po_no`, `dr_no`, and linkage to document table.

---

## 4. API / Route Plan (LOG1)

## 4.1 Material Requests
- `GET /log1/requests` — list requests by status/department/project
- `POST /log1/requests` — create request (item, location, qty, recipient)
- `POST /log1/requests/<id>/approve` — warehouse approve
- `POST /log1/requests/<id>/reject-out-of-stock` — reject and notify requestor
- `POST /log1/requests/<id>/deliver` — mark as delivering/delivered

## 4.2 Procurement + Finance Approval
- `POST /log1/requisitions` — create requisition from out-of-stock request
- `POST /log1/requisitions/<id>/submit-finance` — route to finance
- `POST /finance/approvals/<id>/approve` — finance approval
- `POST /finance/approvals/<id>/reject` — finance rejection

## 4.3 Receiving + Discrepancy
- `POST /log1/receiving` — post received items
- `POST /log1/receiving/<id>/discrepancy` — create discrepancy report
- `POST /log1/discrepancies/<id>/notify-supplier` — notify supplier
- `POST /log1/discrepancies/<id>/resolve` — resolve report

## 4.4 Project Tracking
- `GET /log1/projects/<id>/materials-tracking` — timeline/status
- `POST /log1/projects/<id>/materials-request` — request project materials
- `POST /log1/projects/<id>/status` — set in-progress/completed

## 4.5 Documents
- `POST /log1/documents/auto-record` — auto-record PO/DR metadata + file linkage
- `GET /log1/documents?supplier_id=&doc_type=` — query archived PO/DR docs

---

## 5. UI Implementation Plan

## 5.1 Request Form Changes
- Add required controls:
  - Item selector
  - Storage location selector
  - Quantity
  - Recipient name
  - Recipient label/lang (as configured)
- Validation:
  - Quantity > 0
  - Item and location required

## 5.2 Request Queue Screen
- Status tabs: Pending, For Delivery, Delivered, Rejected (Out of Stock)
- Action buttons:
  - Approve
  - Reject Out of Stock
  - Deliver

## 5.3 Receiving Screen
- Add buttons:
  - Create Discrepancy Report
  - Notify Supplier
- Show discrepancy status badge and correction progress.

## 5.4 Procurement + Finance UI
- Requisition detail includes Finance Approval panel.
- Finance actions:
  - Approve Budget
  - Reject Budget
- Explicit note: no auto deduction unless approved.

## 5.5 Project Real-Time Tracking UI
- Material lifecycle timeline:
  - Request Project Materials
  - Delivering Materials
  - Status (In Progress / Completed)
- Include blocking reason if out-of-stock or budget rejected.

## 5.6 Documents UI
- PO/DR attachment widget on receiving and requisition screens.
- Auto-record confirmation when PO/DR is captured.

---

## 6. Business Rules

1. **No Auto Budget Deduction**: finance ledger is not deducted until finance approval = approved.  
2. **Out-of-Stock Rule**: warehouse can reject request with reason and must notify requestor.  
3. **Escalation Rule**: out-of-stock for project materials triggers purchase requisition to procurement.  
4. **Discrepancy Rule**: receiving mismatch requires discrepancy report and supplier notification option.  
5. **Document Rule**: PO/DR must be auto-recorded and linked to transaction IDs.  
6. **Tracking Rule**: project material stages must be timestamped and user-attributed.

---

## 7. Notifications Plan

- Requestor notified when:
  - Request approved
  - Request rejected out-of-stock
  - Delivery started/completed
- Procurement notified when:
  - Warehouse escalates purchase requisition
- Finance notified when:
  - Budget approval request submitted
- Supplier notified when:
  - Discrepancy report is created and sent

Channels: in-app first, email optional second phase.

---

## 8. Security and Audit

- Role-based permissions:
  - Warehouse: receive/issue/discrepancy
  - Procurement: requisition/sourcing
  - Finance: budget approval decisions
- Audit log on all critical transitions:
  - Out-of-stock rejection
  - Requisition creation
  - Finance approval/rejection
  - Discrepancy creation/notify/resolve
  - Project status update

---

## 9. Phased Delivery Plan

## Phase 1 (Core Request + Stock Decision)
- Request form enhancements (item/location/qty/recipient)
- Out-of-stock rejection + requestor notification
- Warehouse-to-procurement escalation flow

## Phase 2 (Procurement + Finance Control)
- Finance budget approval workflow
- Disable automatic finance deduction
- Requisition approval gates

## Phase 3 (Receiving + Discrepancy)
- Receiving validation
- Create discrepancy report
- Notify supplier button and lifecycle statuses

## Phase 4 (Project Tracking + Documents)
- Real-time project materials tracking
- Project status updates (in progress/completed)
- Auto-record PO/DR documents

---

## 10. Acceptance Criteria

1. Request cannot be submitted without item, location, qty, and recipient fields.  
2. Out-of-stock request triggers rejection notification to requestor within same transaction.  
3. Out-of-stock project request creates procurement requisition automatically.  
4. Finance approval is required before budget is consumed; no auto deduction beforehand.  
5. Receiving discrepancy can be created from receiving screen and supplier can be notified from same flow.  
6. Project tracking reflects live stage transitions with timestamps.  
7. PO/DR are searchable and linked to requisition/receiving records.

---

## 11. Open Clarifications (to confirm before build)

1. `recipient lang` field meaning:
   - If this means language preference, keep as `recipient_lang`.
   - If this means recipient label/name, normalize to `recipient_name` and `recipient_department`.
2. Real-time requirement level:
   - Polling refresh vs websocket push.
3. Supplier notification channels:
   - In-app/email only vs SMS integration.
4. Finance system integration boundary:
   - Internal approval table only vs external accounting sync.

---

## 12. Recommended Build Order in Codebase

1. Database migrations for request/discrepancy/approval/tracking/document tables  
2. LOG1 routes and service functions for requests + stock decisions  
3. Notification service hooks (requestor, procurement, finance, supplier)  
4. Finance approval gating in procurement flow  
5. Receiving discrepancy workflow + supplier notify action  
6. Project tracking timeline endpoints + UI  
7. PO/DR auto-record handlers and linked document views
