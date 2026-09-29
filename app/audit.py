from flask import request
from app import db
from app.models import AuditLog


def log_event(
    user,
    event_type,
    description,
    ip_address=None,
    user_agent=None
):

    log = AuditLog(
        user_id=user.id if user else None,
        event_type=event_type,
        description=description,
        ip_address=ip_address,
        user_agent=user_agent
    )

    db.session.add(log)
    db.session.commit()

    return log