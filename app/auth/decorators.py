from functools import wraps

from flask import abort
from flask_login import current_user


# ============================================================
# ROLE-BASED ACCESS CONTROL
# ============================================================

def role_required(*allowed_roles):

    def decorator(view_function):

        @wraps(view_function)
        def wrapped_view(*args, **kwargs):

            # ------------------------------------------------
            # User must be logged in
            # ------------------------------------------------

            if not current_user.is_authenticated:
                abort(401)

            # ------------------------------------------------
            # Check user's role
            # ------------------------------------------------

            if current_user.role not in allowed_roles:
                abort(403)

            # ------------------------------------------------
            # Permission granted
            # ------------------------------------------------

            return view_function(
                *args,
                **kwargs
            )

        return wrapped_view

    return decorator