# LOG2 — Fleet Operations: Implementation Plan
**Date:** 2026-03-13  
**Status:** Planning  
**Subsystem:** LOG2 — Fleet Ops  

---

## 1. Overview

LOG2 is the Fleet Operations module of the HMS Logistics division. The current system provides basic fleet and trip tracking. This plan covers a full upgrade of LOG2 into an intelligent, cost-aware fleet management system with anomaly detection, driver performance monitoring, finance integration, and automated cost optimization recommendations.

---

## 2. Scope of Changes

### 2a. Features to Implement (New)

| # | Feature | Module Area |
|---|---------|-------------|
| 1 | Mileage / Fuel / Usage Tracking | Vehicle Management |
| 2 | Maintenance Schedule per Vehicle | Vehicle Management |
| 3 | Fleet Performance Dashboard | Vehicle Management |
| 4 | Driver & Trip Performance Monitoring | Driver Management |
| 5 | Auto-Detect Anomalies & Alert Driver | Driver Management |
| 6 | Notification Placement Logic | System-wide |
| 7 | Route & Schedule Optimization | Cost Analysis |
| 8 | Vehicle / Carrier Evaluation | Cost Analysis |
| 9 | Budget Data pull from Finance | Cost Analysis |
| 10 | Cost Optimization Recommendations → Finance | Cost Analysis |

### 2b. Features to Modify (Existing)

| Feature | Change |
|---------|--------|
| Transport Cost Analysis & Optimization | Move from **during-operation** to **after-operation** post-trip analysis pipeline |

---

## 3. Database Schema Changes

### 3a. New/Modified Tables

#### `vehicle_mileage_logs`
```sql
CREATE TABLE IF NOT EXISTS vehicle_mileage_logs (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT NOT NULL,
    trip_id BIGINT,
    odometer_start NUMERIC(10,2),
    odometer_end NUMERIC(10,2),
    mileage_km NUMERIC(10,2) GENERATED ALWAYS AS (odometer_end - odometer_start) STORED,
    fuel_used_liters NUMERIC(8,2),
    fuel_cost NUMERIC(10,2),
    logged_by BIGINT,
    logged_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `vehicle_maintenance_schedules`
```sql
CREATE TABLE IF NOT EXISTS vehicle_maintenance_schedules (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT NOT NULL,
    maintenance_type TEXT NOT NULL,          -- OIL_CHANGE, TIRE_ROTATION, BRAKE_CHECK, etc.
    scheduled_date DATE NOT NULL,
    last_done_date DATE,
    interval_km NUMERIC(10,2),              -- km-based trigger
    interval_days INT,                       -- day-based trigger
    status TEXT NOT NULL DEFAULT 'UPCOMING', -- UPCOMING, DUE, OVERDUE, COMPLETED
    assigned_to BIGINT,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `driver_trip_performance`
```sql
CREATE TABLE IF NOT EXISTS driver_trip_performance (
    id BIGSERIAL PRIMARY KEY,
    driver_id BIGINT NOT NULL,
    trip_id BIGINT NOT NULL,
    vehicle_id BIGINT,
    start_time TIMESTAMPTZ,
    end_time TIMESTAMPTZ,
    distance_km NUMERIC(10,2),
    fuel_used_liters NUMERIC(8,2),
    avg_speed_kmh NUMERIC(6,2),
    harsh_braking_count INT DEFAULT 0,
    harsh_acceleration_count INT DEFAULT 0,
    idle_time_minutes INT DEFAULT 0,
    on_time_delivery BOOLEAN,
    performance_score NUMERIC(4,2),          -- computed 0–100
    anomalies JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `fleet_anomalies`
```sql
CREATE TABLE IF NOT EXISTS fleet_anomalies (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT,
    driver_id BIGINT,
    trip_id BIGINT,
    anomaly_type TEXT NOT NULL,              -- EXCESSIVE_FUEL, ROUTE_DEVIATION, IDLE_OVERRUN, HARSH_DRIVING, MAINTENANCE_OVERDUE
    severity TEXT NOT NULL DEFAULT 'LOW',    -- LOW, MEDIUM, HIGH, CRITICAL
    description TEXT,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by BIGINT,
    acknowledged_at TIMESTAMPTZ,
    auto_notified BOOLEAN DEFAULT FALSE
);
```

#### `cost_analysis_reports`
```sql
CREATE TABLE IF NOT EXISTS cost_analysis_reports (
    id BIGSERIAL PRIMARY KEY,
    report_no TEXT UNIQUE NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    vehicle_id BIGINT,
    route_id BIGINT,
    total_fuel_cost NUMERIC(14,2) DEFAULT 0,
    total_maintenance_cost NUMERIC(14,2) DEFAULT 0,
    total_driver_cost NUMERIC(14,2) DEFAULT 0,
    total_cost NUMERIC(14,2) DEFAULT 0,
    budget_allocated NUMERIC(14,2) DEFAULT 0,   -- pulled from finance
    budget_variance NUMERIC(14,2),               -- total_cost - budget_allocated
    optimization_suggestions JSONB DEFAULT '[]',
    sent_to_finance BOOLEAN DEFAULT FALSE,
    sent_at TIMESTAMPTZ,
    created_by BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `vehicle_carrier_evaluations`
```sql
CREATE TABLE IF NOT EXISTS vehicle_carrier_evaluations (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT,
    carrier_name TEXT,
    evaluation_period TEXT,
    reliability_score NUMERIC(4,2),
    cost_efficiency_score NUMERIC(4,2),
    maintenance_compliance_score NUMERIC(4,2),
    overall_score NUMERIC(4,2),
    recommendation TEXT,                        -- RETAIN, REVIEW, REPLACE
    notes TEXT,
    evaluated_by BIGINT,
    evaluated_at TIMESTAMPTZ DEFAULT NOW()
);
```

#### `ALTER` on existing tables
```sql
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS current_odometer NUMERIC(10,2) DEFAULT 0;
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS fuel_capacity_liters NUMERIC(8,2);
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS last_maintenance_date DATE;
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS next_maintenance_date DATE;
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS maintenance_status TEXT DEFAULT 'OK'; -- OK, DUE, OVERDUE

ALTER TABLE trips ADD COLUMN IF NOT EXISTS distance_km NUMERIC(10,2);
ALTER TABLE trips ADD COLUMN IF NOT EXISTS fuel_cost NUMERIC(10,2);
ALTER TABLE trips ADD COLUMN IF NOT EXISTS driver_performance_id BIGINT;
ALTER TABLE trips ADD COLUMN IF NOT EXISTS post_trip_analysis_done BOOLEAN DEFAULT FALSE;
```

---

## 4. Feature Specifications

### 4.1 Mileage / Fuel / Usage Tracking

**Where:** Vehicle detail page → new "Mileage & Fuel" tab  
**Trigger:** Driver submits a trip completion form with odometer readings and fuel fill-up data  
**Logic:**
- `mileage_km = odometer_end - odometer_start`
- `fuel_efficiency = mileage_km / fuel_used_liters` (km/L)
- Running total stored on `vehicles.current_odometer`
- Fuel cost auto-logged to `vehicle_mileage_logs`
- Anomaly check: if `fuel_efficiency < fleet_avg * 0.75` → trigger `EXCESSIVE_FUEL` anomaly

**UI Components:**
- Chart: Fuel Efficiency over time (line chart per vehicle)
- Chart: Monthly mileage bar chart
- Usage heatmap per vehicle (Mon–Sun)

---

### 4.2 Maintenance Schedule per Vehicle

**Where:** Vehicle detail page → "Maintenance" tab + Fleet Dashboard alerts  
**Types:** Oil Change, Tire Rotation, Brake Check, Battery, General Inspection  
**Trigger Rules:**
- `interval_km`: auto-flag when `current_odometer - last_done_odometer >= interval_km`
- `interval_days`: auto-flag when `today - last_done_date >= interval_days`
- Status transitions: `UPCOMING → DUE → OVERDUE → COMPLETED`

**Automated Actions:**
- When status becomes `DUE`: notify LOG2 admin + driver
- When status becomes `OVERDUE`: escalate to LOG2 supervisor + flag vehicle as restricted
- When `COMPLETED`: update `last_done_date`, reset trigger, set next schedule

**UI Components:**
- Maintenance calendar view per vehicle
- Overdue alerts banner on Fleet Dashboard
- Quick-complete button with form (date, cost, mechanic)

---

### 4.3 Fleet Performance Dashboard

**Where:** LOG2 Dashboard (redesign top section)  
**Metrics displayed:**
| Metric | Source |
|--------|--------|
| Total Active Vehicles | `vehicles` table |
| Vehicles Due for Maintenance | `vehicle_maintenance_schedules` |
| Fleet Avg Fuel Efficiency | `vehicle_mileage_logs` aggregation |
| Active Trips | `trips` status = In Progress |
| Anomalies This Week | `fleet_anomalies` last 7 days |
| Fleet Utilization Rate | trips / available vehicle-days |

**Charts:**
- Fleet utilization rate (weekly bar)
- Cost per vehicle (stacked: fuel + maintenance + driver)
- Top 5 most-used vehicles
- Bottom 5 performers (performance score)

---

### 4.4 Driver & Trip Performance Monitoring

**Where:** LOG2 → Drivers section → Driver Profile → Performance tab  
**Data collected per trip:**
- Distance driven
- Fuel consumed
- Average speed
- Idle time
- On-time delivery (vs scheduled arrival)
- Harsh events (braking/acceleration — manual entry or future GPS integration)

**Score Computation (0–100):**
```
performance_score = (
    on_time_weight     * (1 if on_time else 0)         * 30  +
    fuel_weight        * min(fuel_efficiency / target, 1) * 25  +
    harsh_events_weight * max(0, 1 - harsh_count / 10)   * 25  +
    idle_weight        * max(0, 1 - idle_minutes / 60)   * 20
)
```

**UI Components:**
- Driver scorecard (score badge, trend arrow)
- Trip history table with per-trip scores
- Comparison chart: this driver vs fleet average

---

### 4.5 Auto-Detect Anomalies & Alert Driver

**Triggered:** On trip completion POST and on daily scheduled check  
**Anomaly Types & Thresholds:**

| Anomaly | Trigger Condition | Severity |
|---------|-------------------|----------|
| `EXCESSIVE_FUEL` | fuel efficiency < 75% of fleet avg | MEDIUM |
| `ROUTE_DEVIATION` | actual distance > planned distance * 1.2 | HIGH |
| `IDLE_OVERRUN` | idle time > 60 min | LOW |
| `HARSH_DRIVING` | harsh events > 5 per trip | MEDIUM |
| `MAINTENANCE_OVERDUE` | vehicle maintenance status = OVERDUE | HIGH |
| `COST_SPIKE` | trip fuel cost > avg * 1.5 | MEDIUM |

**Notification Placement Logic:**
- `LOW`: Bell notification to LOG2 admin only (in-app)
- `MEDIUM`: Bell notification to LOG2 admin + driver's own portal notification + dashboard alert card
- `HIGH`: Bell notification to LOG2 admin + driver + LOG2 supervisor + dashboard banner
- `CRITICAL`: All above + email/SMS placeholder + block vehicle assignment until acknowledged

**Auto-notify on detect:**
```python
if anomaly.severity in ('HIGH', 'CRITICAL'):
    Notification.create(subsystem='log2', user_id=driver_user_id, ...)
    Notification.create(subsystem='log2', user_id=log2_admin_id, ...)
elif anomaly.severity == 'MEDIUM':
    Notification.create(subsystem='log2', user_id=log2_admin_id, ...)
```

---

### 4.6 Route & Schedule Optimization (Cost Analysis)

**Where:** LOG2 → Cost Analysis tab → Route Optimizer section  
**Logic:**
- After-trip analysis: compare planned vs actual route distance & time
- Group trips by corridor (origin–destination pair)
- Calculate average cost per corridor
- Identify corridors with cost > fleet average + 20% → flag for review
- Suggested schedule shifts: move high-cost time slots to off-peak

**Output:**
- Route efficiency table (corridor | avg cost | trips | vs baseline)
- Recommended schedule adjustments (text + table)
- Saved as `optimization_suggestions` JSONB in `cost_analysis_reports`

---

### 4.7 Vehicle / Carrier Evaluation (Cost Analysis)

**Where:** LOG2 → Cost Analysis → Carrier Evaluation  
**Evaluated per vehicle or external carrier:**
- Reliability score: % on-time trips
- Cost efficiency: actual cost vs budgeted cost
- Maintenance compliance: % scheduled maintenance completed on time
- Overall score = weighted average

**Recommendation thresholds:**
| Score | Recommendation |
|-------|----------------|
| ≥ 80 | RETAIN |
| 60–79 | REVIEW |
| < 60 | REPLACE |

---

### 4.8 Budget Data from Finance (Cost Analysis)

**Integration:** Read-only pull from Finance module  
**Data pulled:** 
- Finance budget allocations tagged as `category = 'Fleet'` or `subsystem = 'log2'`
- Pulled via existing `procurement_budget_approvals` or a dedicated `department_budgets` table

**Display:**
- Budget vs Actual cost card on Cost Analysis page
- Variance indicator (over/under budget with %)

---

### 4.9 Cost Optimization Recommendations → Finance

**Where:** LOG2 → Cost Analysis → Generate Report button  
**Process:**
1. System computes period cost totals
2. Generates `optimization_suggestions` list (JSON array of actionable items)
3. Admin reviews and clicks "Send to Finance"
4. Creates a `Notification` in the Finance subsystem with report summary
5. Marks `cost_analysis_reports.sent_to_finance = TRUE`

**Example suggestion payload:**
```json
[
  {"type": "ROUTE", "route": "Hospital → Depot A", "saving": 4200, "action": "Consolidate 3 daily trips into 2"},
  {"type": "VEHICLE", "vehicle": "TRK-003", "saving": 8500, "action": "Replace with newer unit — maintenance cost exceeds value"},
  {"type": "FUEL", "vehicle": "VAN-07", "saving": 2100, "action": "Investigate fuel consumption anomaly — 40% above fleet avg"}
]
```

---

### 4.10 Transport Cost Analysis — Move to Post-Operation

**Current behavior:** Cost analysis runs concurrently with active trips  
**New behavior:** Cost analysis runs only after a trip is marked `Completed`

**Change:**
- Add `post_trip_analysis_done BOOLEAN` to `trips`
- `update_trip_status()` route: when status → `Completed`, auto-trigger `_run_post_trip_analysis(trip_id)`
- `_run_post_trip_analysis()` helper:
  1. Create `driver_trip_performance` record
  2. Update `vehicle_mileage_logs`
  3. Run anomaly detection
  4. Update `vehicles.current_odometer`
  5. Check maintenance schedule triggers
  6. Set `post_trip_analysis_done = TRUE`

---

## 5. UI Pages / Routes Needed

| Route | Template | Description |
|-------|----------|-------------|
| `GET /log2/fleet` | `fleet_dashboard.html` | Redesigned fleet overview with KPI cards/charts |
| `GET /log2/vehicle/<id>/maintenance` | `vehicle_maintenance.html` | Maintenance schedule & history |
| `POST /log2/vehicle/<id>/maintenance/add` | — | Add/update maintenance record |
| `GET /log2/vehicle/<id>/mileage` | `vehicle_mileage.html` | Mileage & fuel log tab |
| `POST /log2/trip/<id>/complete` | — | Mark trip done, trigger post-trip analysis |
| `GET /log2/drivers/<id>/performance` | `driver_performance.html` | Driver scorecard & trip history |
| `GET /log2/cost-analysis` | `cost_analysis.html` | Cost analysis hub |
| `POST /log2/cost-analysis/generate` | — | Generate period report |
| `POST /log2/cost-analysis/<id>/send-to-finance` | — | Push recommendations to Finance |
| `GET /log2/anomalies` | `anomalies.html` | Anomaly log with acknowledge actions |

---

## 6. Notification Placement Summary

| Event | Who gets notified | Channel |
|-------|-------------------|---------|
| Maintenance DUE | LOG2 Admin | In-app bell |
| Maintenance OVERDUE | LOG2 Admin + Supervisor | In-app bell + dashboard banner |
| Anomaly LOW | LOG2 Admin | In-app bell |
| Anomaly MEDIUM | LOG2 Admin + Driver | In-app bell + driver alert card |
| Anomaly HIGH | LOG2 Admin + Driver + Supervisor | In-app bell + banner |
| Cost report sent to Finance | Finance Admin | In-app bell |
| Budget overspend detected | LOG2 Admin + Finance Admin | In-app bell |

---

## 7. Implementation Phases

### Phase 1 — Foundation (Week 1)
- [ ] Run `log2_migration.sql` — create all new tables + ALTER existing
- [ ] `_run_post_trip_analysis()` helper function
- [ ] Mileage & fuel log form + route
- [ ] Move cost analysis to post-operation trigger

### Phase 2 — Vehicle Management (Week 2)
- [ ] Maintenance schedule CRUD
- [ ] Auto-status transitions (UPCOMING → DUE → OVERDUE)
- [ ] Fleet performance dashboard KPI cards
- [ ] Vehicle maintenance tab template

### Phase 3 — Driver & Anomaly (Week 3)
- [ ] Driver trip performance record creation
- [ ] Performance score computation
- [ ] Anomaly detection engine (`_detect_trip_anomalies()`)
- [ ] Notification placement per severity
- [ ] Driver scorecard template

### Phase 4 — Cost Analysis (Week 4)
- [ ] Route & schedule optimization logic
- [ ] Vehicle/carrier evaluation scoring
- [ ] Finance budget pull integration
- [ ] Cost analysis report generation
- [ ] Send-to-finance notification flow
- [ ] Cost analysis hub template

---

## 8. Migration File

All DDL will be added to `log2_migration.sql`:
```sql
-- Run after log1_migration.sql
-- LOG2 Fleet Operations Extended Schema
-- Phase 1: Core tables
CREATE TABLE IF NOT EXISTS vehicle_mileage_logs ( ... );
CREATE TABLE IF NOT EXISTS vehicle_maintenance_schedules ( ... );
CREATE TABLE IF NOT EXISTS driver_trip_performance ( ... );
CREATE TABLE IF NOT EXISTS fleet_anomalies ( ... );
CREATE TABLE IF NOT EXISTS cost_analysis_reports ( ... );
CREATE TABLE IF NOT EXISTS vehicle_carrier_evaluations ( ... );

-- Phase 1: Column additions
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS current_odometer NUMERIC(10,2) DEFAULT 0;
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS fuel_capacity_liters NUMERIC(8,2);
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS last_maintenance_date DATE;
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS next_maintenance_date DATE;
ALTER TABLE vehicles ADD COLUMN IF NOT EXISTS maintenance_status TEXT DEFAULT 'OK';
ALTER TABLE trips ADD COLUMN IF NOT EXISTS distance_km NUMERIC(10,2);
ALTER TABLE trips ADD COLUMN IF NOT EXISTS fuel_cost NUMERIC(10,2);
ALTER TABLE trips ADD COLUMN IF NOT EXISTS post_trip_analysis_done BOOLEAN DEFAULT FALSE;
```

---

## 9. Dependencies

- Finance module (`financials.main`) — budget data read access
- `notifications` table — for anomaly + report alerts
- `users` table — driver user_id linkage
- `vehicles` table — existing LOG2 vehicle records
- `trips` table — existing LOG2 trip records
