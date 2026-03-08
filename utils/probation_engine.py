"""
Probation Cycle State Machine Engine.
Manages the full probationary performance cycle workflow for hospital staff.
"""

from datetime import datetime, timedelta
from utils.supabase_client import get_supabase_client


class ProbationStage:
    """Enum-like constants for probation stages."""
    ASSIGNED = 'ASSIGNED'
    KPI_SETUP = 'KPI_SETUP'
    KPI_ACKNOWLEDGED = 'KPI_ACKNOWLEDGED'
    MONITORING = 'MONITORING'
    MID_CHECK_IN = 'MID_CHECK_IN'
    DOCUMENTATION = 'DOCUMENTATION'
    FINAL_EVALUATION = 'FINAL_EVALUATION'
    RECOMMENDATION = 'RECOMMENDATION'
    HR_DECISION = 'HR_DECISION'

    ALL_STAGES = [
        ASSIGNED, KPI_SETUP, KPI_ACKNOWLEDGED, MONITORING,
        MID_CHECK_IN, DOCUMENTATION, FINAL_EVALUATION,
        RECOMMENDATION, HR_DECISION
    ]

    LABELS = {
        ASSIGNED: 'Employee Assigned to Supervisor',
        KPI_SETUP: 'Set Performance Standards & KPIs',
        KPI_ACKNOWLEDGED: 'KPI Acknowledgement',
        MONITORING: 'Ongoing Monitoring & Coaching',
        MID_CHECK_IN: 'Mid-Probation Check-in',
        DOCUMENTATION: 'Documentation of Performance Notes',
        FINAL_EVALUATION: 'Final Probation Evaluation',
        RECOMMENDATION: 'Supervisor Recommendation',
        HR_DECISION: 'HR Final Decision & Notice',
    }

    ICONS = {
        ASSIGNED: 'person-check',
        KPI_SETUP: 'list-check',
        KPI_ACKNOWLEDGED: 'hand-thumbs-up',
        MONITORING: 'eye',
        MID_CHECK_IN: 'clipboard2-check',
        DOCUMENTATION: 'journal-text',
        FINAL_EVALUATION: 'graph-up-arrow',
        RECOMMENDATION: 'send-check',
        HR_DECISION: 'shield-check',
    }


# Valid transitions: each stage can only move to the next in sequence
STAGE_TRANSITIONS = {
    ProbationStage.ASSIGNED: [ProbationStage.KPI_SETUP],
    ProbationStage.KPI_SETUP: [ProbationStage.KPI_ACKNOWLEDGED],
    ProbationStage.KPI_ACKNOWLEDGED: [ProbationStage.MONITORING],
    ProbationStage.MONITORING: [ProbationStage.MID_CHECK_IN],
    ProbationStage.MID_CHECK_IN: [ProbationStage.DOCUMENTATION],
    ProbationStage.DOCUMENTATION: [ProbationStage.FINAL_EVALUATION],
    ProbationStage.FINAL_EVALUATION: [ProbationStage.RECOMMENDATION],
    ProbationStage.RECOMMENDATION: [ProbationStage.HR_DECISION],
    ProbationStage.HR_DECISION: [],  # Terminal
}


def can_advance(current_stage: str, target_stage: str) -> bool:
    """Check if a transition from current_stage to target_stage is valid."""
    return target_stage in STAGE_TRANSITIONS.get(current_stage, [])


def get_stage_index(stage: str) -> int:
    """Get the index of a stage in the workflow (0-based)."""
    try:
        return ProbationStage.ALL_STAGES.index(stage)
    except ValueError:
        return -1


def get_stage_progress(stage: str) -> int:
    """Get the progress percentage for a stage."""
    idx = get_stage_index(stage)
    if idx < 0:
        return 0
    total = len(ProbationStage.ALL_STAGES)
    return int(((idx + 1) / total) * 100)


def calculate_end_date(start_date, days=90):
    """Calculate probation end date from start date."""
    if isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    return start_date + timedelta(days=days)


def advance_stage(cycle_id: int, target_stage: str, user_id: int):
    """
    Validate and advance the probation cycle to the next stage.
    
    Args:
        cycle_id: The ID of the probation cycle
        target_stage: The stage to advance to
        user_id: The ID of the user performing the action
    
    Raises:
        ValueError: If the transition is not valid
    """
    client = get_supabase_client()
    
    cycle_resp = client.table('probation_cycles').select('*').eq('id', cycle_id).single().execute()
    if not cycle_resp.data:
        raise ValueError("Probation cycle not found.")
    
    cycle = cycle_resp.data
    current = cycle['current_stage']
    
    if not can_advance(current, target_stage):
        raise ValueError(
            f"Cannot transition from '{ProbationStage.LABELS.get(current, current)}' "
            f"to '{ProbationStage.LABELS.get(target_stage, target_stage)}'. "
            f"Steps cannot be skipped."
        )
    
    client.table('probation_cycles').update({
        'current_stage': target_stage,
        'updated_at': datetime.utcnow().isoformat()
    }).eq('id', cycle_id).execute()
    
    # Send stage-specific notifications
    _send_stage_notification(cycle, target_stage, user_id)
    
    return True


def _send_stage_notification(cycle: dict, new_stage: str, actor_id: int):
    """Send notifications when a probation cycle advances to a new stage."""
    from utils.hms_models import Notification
    
    employee_id = cycle.get('employee_id')
    supervisor_id = cycle.get('supervisor_id')
    stage_label = ProbationStage.LABELS.get(new_stage, new_stage)
    
    # Determine notification targets based on stage
    if new_stage == ProbationStage.KPI_SETUP:
        # Notify supervisor to set KPIs
        Notification.create(
            user_id=supervisor_id,
            subsystem='hr1',
            title="KPI Setup Required",
            message=f"Please set performance standards and KPIs for the probation cycle.",
            n_type="info",
            sender_subsystem='hr1'
        )
    elif new_stage == ProbationStage.KPI_ACKNOWLEDGED:
        # Notify employee to acknowledge KPIs
        Notification.create(
            user_id=employee_id,
            subsystem='hr1',
            title="KPI Acknowledgement Required",
            message=f"Your performance KPIs have been set. Please review and acknowledge them.",
            n_type="warning",
            sender_subsystem='hr1'
        )
    elif new_stage == ProbationStage.MID_CHECK_IN:
        # Notify both
        Notification.create(
            user_id=supervisor_id,
            subsystem='hr1',
            title="Mid-Probation Check-in Due",
            message=f"A mid-probation check-in is due. Please complete the assessment form.",
            n_type="warning",
            sender_subsystem='hr1'
        )
        Notification.create(
            user_id=employee_id,
            subsystem='hr1',
            title="Mid-Probation Check-in Scheduled",
            message=f"Your supervisor will conduct a mid-probation check-in soon.",
            n_type="info",
            sender_subsystem='hr1'
        )
    elif new_stage == ProbationStage.FINAL_EVALUATION:
        Notification.create(
            user_id=supervisor_id,
            subsystem='hr1',
            title="Final Evaluation Due",
            message=f"The final probation evaluation is now due. Please complete the evaluation form.",
            n_type="danger",
            sender_subsystem='hr1'
        )
    elif new_stage == ProbationStage.HR_DECISION:
        # Notify all HR admins
        Notification.create(
            subsystem='hr1',
            role='Admin',
            title="HR Decision Required",
            message=f"A supervisor recommendation has been submitted. HR review and final decision required.",
            n_type="danger",
            sender_subsystem='hr1'
        )


def create_probation_cycle(employee_id: int, supervisor_id: int, cycle_type: str = 'New Hire',
                           start_date=None, duration_days: int = 90):
    """
    Create a new probation cycle for an employee.
    
    Args:
        employee_id: The employee's user ID
        supervisor_id: The supervisor's user ID
        cycle_type: Type of probation (New Hire, Promotion, Transfer, Reassignment)
        start_date: Start date (defaults to today)
        duration_days: Duration in days (default 90)
    
    Returns:
        The created probation cycle data
    """
    client = get_supabase_client()
    
    if start_date is None:
        start_date = datetime.utcnow().date()
    elif isinstance(start_date, str):
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    
    end_date = calculate_end_date(start_date, duration_days)
    
    data = {
        'employee_id': employee_id,
        'supervisor_id': supervisor_id,
        'cycle_type': cycle_type,
        'start_date': start_date.isoformat(),
        'end_date': end_date.isoformat(),
        'current_stage': ProbationStage.ASSIGNED,
        'status': 'Active',
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }
    
    response = client.table('probation_cycles').insert(data).execute()
    
    if response.data:
        # Notify supervisor
        from utils.hms_models import Notification
        Notification.create(
            user_id=supervisor_id,
            subsystem='hr1',
            title="New Probation Cycle Assigned",
            message=f"You have been assigned as supervisor for a new {cycle_type.lower()} probation cycle.",
            n_type="info",
            sender_subsystem='hr1'
        )
        return response.data[0]
    
    return None
