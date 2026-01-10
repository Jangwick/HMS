# Implementation Plan: User Registration & HR3 Approval System

## Overview
This document outlines the implementation plan for a distributed User Registration system where each subsystem has its own registration form, but all new accounts must be reviewed and approved/denied by the **HR3 (Benefits Administration)** admin team.

## 1. Security & Password Policies (Mandatory)
All passwords (Admin and User) must adhere to these strict rules:
- **Length**: 8 to 14 characters.
- **Complexity**: 1+ Uppercase, 1+ Number, 1+ Special Character.
- **Uniqueness**: No duplicate passwords across the entire system (all departments).
- **Expiration**: Mandatory change every 90 days.
- **History**: Cannot reuse the last 5 passwords.

## 2. Distributed Registration Workflow

### 2.1 Subsystem Registration Forms
- Each subsystem (e.g., HR1, CT1, FIN1) will have a `/register` route.
- The registration form will collect:
    - Username
    - Email
    - Password (validated against global rules)
    - Department/Subsystem (automatically set based on the route)
- **Initial Status**: All new registrations are created with `status = 'Pending'`.
- **Access Control**: Users with 'Pending' status cannot log in.

### 2.2 Centralized HR3 Approval Dashboard
- **Location**: `/hr3/admin/approvals`
- **Features**:
    - List all 'Pending' users across all departments.
    - View user details (Username, Email, Department, Registration Date).
    - **Approve**: Changes status to 'Active', allowing the user to log in.
    - **Deny**: Deletes the pending request or marks it as 'Rejected'.

## 3. Technical Implementation

### Step 1: Database Schema Update (Supabase)
- Add a `status` column to the `users` table (Enum: `Pending`, `Active`, `Rejected`).
- Default value for new records: `Pending`.

### Step 2: Shared Registration Logic (utils/auth_utils.py)
- Create a reusable registration function that subsystems can call.
- This function will:
    - Validate password complexity and global uniqueness.
    - Insert the user into Supabase with `status='Pending'`.

### Step 3: Subsystem Registration Routes
- Implement `/register` in each blueprint (or a shared route that detects the subsystem).
- Example: `routes/hr/hr1.py` -> `@hr1_bp.route('/register')`.

### Step 4: HR3 Admin Approval Routes (routes/hr/hr3.py)
- `@hr3_bp.route('/admin/approvals')`: List pending users.
- `@hr3_bp.route('/admin/approvals/<id>/approve')`: Set status to 'Active'.
- `@hr3_bp.route('/admin/approvals/<id>/deny')`: Set status to 'Rejected' or delete.

### Step 5: Login Logic Update (utils/supabase_client.py)
- Update `User.check_password` or the login route to check if `status == 'Active'`.
- If 'Pending', show a message: "Your account is awaiting approval from HR3."

## 4. UI/UX Requirements
- **Registration Form**: Premium design with real-time password strength indicators.
- **Approval Dashboard**: Clean table with quick action buttons (Checkmark for Approve, X for Deny).
- **Notifications**: (Optional) Email notification to the user when approved.

## 5. Implementation Status
- [x] Implementation Plan (this doc)
- [ ] Database `status` column addition
- [ ] Shared Registration Route/Logic
- [ ] HR3 Approval Dashboard UI
- [ ] HR3 Approval Backend Logic
- [ ] Login Status Check
