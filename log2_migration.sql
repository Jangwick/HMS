-- LOG2 Fleet Operations Extended Schema
-- Date: 2026-03-13

CREATE TABLE IF NOT EXISTS vehicle_mileage_logs (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT NOT NULL,
    trip_id BIGINT,
    odometer_start NUMERIC(10,2),
    odometer_end NUMERIC(10,2),
    mileage_km NUMERIC(10,2),
    fuel_used_liters NUMERIC(8,2),
    fuel_cost NUMERIC(10,2),
    fuel_efficiency_kmpl NUMERIC(8,2),
    logged_by BIGINT,
    logged_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vehicle_maintenance_schedules (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT NOT NULL,
    maintenance_type TEXT NOT NULL,
    scheduled_date DATE NOT NULL,
    last_done_date DATE,
    interval_km NUMERIC(10,2),
    interval_days INT,
    status TEXT NOT NULL DEFAULT 'UPCOMING',
    assigned_to BIGINT,
    notes TEXT,
    completed_cost NUMERIC(12,2),
    completed_by BIGINT,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

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
    performance_score NUMERIC(5,2),
    anomalies JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS fleet_anomalies (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT,
    driver_id BIGINT,
    trip_id BIGINT,
    anomaly_type TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'LOW',
    description TEXT,
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by BIGINT,
    acknowledged_at TIMESTAMPTZ,
    auto_notified BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS cost_analysis_reports (
    id BIGSERIAL PRIMARY KEY,
    report_no TEXT UNIQUE NOT NULL,
    period_start DATE NOT NULL,
    period_end DATE NOT NULL,
    vehicle_id BIGINT,
    route_key TEXT,
    total_fuel_cost NUMERIC(14,2) DEFAULT 0,
    total_maintenance_cost NUMERIC(14,2) DEFAULT 0,
    total_driver_cost NUMERIC(14,2) DEFAULT 0,
    total_cost NUMERIC(14,2) DEFAULT 0,
    budget_allocated NUMERIC(14,2) DEFAULT 0,
    budget_variance NUMERIC(14,2),
    optimization_suggestions JSONB DEFAULT '[]',
    sent_to_finance BOOLEAN DEFAULT FALSE,
    sent_at TIMESTAMPTZ,
    created_by BIGINT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vehicle_carrier_evaluations (
    id BIGSERIAL PRIMARY KEY,
    vehicle_id BIGINT,
    carrier_name TEXT,
    evaluation_period TEXT,
    reliability_score NUMERIC(5,2),
    cost_efficiency_score NUMERIC(5,2),
    maintenance_compliance_score NUMERIC(5,2),
    overall_score NUMERIC(5,2),
    recommendation TEXT,
    notes TEXT,
    evaluated_by BIGINT,
    evaluated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS current_odometer NUMERIC(10,2) DEFAULT 0;
ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS fuel_capacity_liters NUMERIC(8,2);
ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS last_maintenance_date DATE;
ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS next_maintenance_date DATE;
ALTER TABLE fleet_vehicles ADD COLUMN IF NOT EXISTS maintenance_status TEXT DEFAULT 'OK';

ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS distance_km NUMERIC(10,2);
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS fuel_used_liters NUMERIC(8,2);
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS fuel_cost NUMERIC(10,2);
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS odometer_start NUMERIC(10,2);
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS odometer_end NUMERIC(10,2);
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS idle_time_minutes INT DEFAULT 0;
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS harsh_braking_count INT DEFAULT 0;
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS harsh_acceleration_count INT DEFAULT 0;
ALTER TABLE fleet_dispatch ADD COLUMN IF NOT EXISTS post_trip_analysis_done BOOLEAN DEFAULT FALSE;

ALTER TABLE fleet_costs ADD COLUMN IF NOT EXISTS dispatch_id BIGINT;

CREATE INDEX IF NOT EXISTS idx_vehicle_mileage_logs_vehicle_id ON vehicle_mileage_logs(vehicle_id);
CREATE INDEX IF NOT EXISTS idx_vehicle_maintenance_schedules_vehicle_id ON vehicle_maintenance_schedules(vehicle_id);
CREATE INDEX IF NOT EXISTS idx_driver_trip_performance_driver_id ON driver_trip_performance(driver_id);
CREATE INDEX IF NOT EXISTS idx_fleet_anomalies_detected_at ON fleet_anomalies(detected_at);
CREATE INDEX IF NOT EXISTS idx_cost_analysis_reports_period ON cost_analysis_reports(period_start, period_end);
