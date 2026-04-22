import secrets
import time
import common.vars as common_vars

sessions = dict()
session_timestamps = dict()  # Track when sessions were created
session_last_activity = dict()  # Track last activity for session renewal

# Session expiration time - can be configured
_session_expiration_time = common_vars.SESSION_EXPIRATION_TIME


def set_session_expiration_time(seconds):
    """Set the session expiration time in seconds"""
    global _session_expiration_time
    _session_expiration_time = seconds


def get_session_expiration_time():
    """Get the current session expiration time in seconds"""
    return _session_expiration_time


def create_new_session(user):
    new_session_id = secrets.token_urlsafe(16)
    while sessions.get(new_session_id, None) is not None:
        new_session_id = secrets.token_urlsafe(16)
    session_id = new_session_id
    sessions[session_id] = user
    session_timestamps[session_id] = time.time()
    session_last_activity[session_id] = time.time()
    return session_id


def get_username_by_session_id(id):
    # Check if session has expired
    if id in session_timestamps:
        session_age = time.time() - session_timestamps[id]
        if session_age > _session_expiration_time:  # Session expired
            remove_session(id)
            return None
    username = sessions.get(id, None)
    if username:
        # Update last activity
        session_last_activity[id] = time.time()
    return username


def get_session_age(session_id):
    """Get the age of a session in seconds"""
    if session_id in session_timestamps:
        return time.time() - session_timestamps[session_id]
    return None


def is_session_expiring_soon(session_id, warning_minutes=5):
    """Check if session is expiring soon (within warning_minutes)"""
    age = get_session_age(session_id)
    if age is None:
        return False
    warning_seconds = warning_minutes * 60
    return age > (_session_expiration_time - warning_seconds)


def renew_session(session_id):
    """Renew a session by updating its timestamp"""
    if session_id in sessions:
        session_timestamps[session_id] = time.time()
        session_last_activity[session_id] = time.time()
        return True
    return False


def remove_session(session_id):
    """Remove a specific session by ID"""
    if session_id in sessions:
        user = sessions.pop(session_id)
        session_timestamps.pop(session_id, None)
        session_last_activity.pop(session_id, None)
        return user
    return None


def remove_existing_session(uname):
    """Remove all sessions for a specific user (for cleanup)"""
    removed_count = 0
    session_ids_to_remove = []

    for session_id, user in sessions.items():
        if user == uname:
            session_ids_to_remove.append(session_id)

    for session_id in session_ids_to_remove:
        remove_session(session_id)
        removed_count += 1

    return removed_count > 0


def get_session_id_by_username(uname):
    for id, u in sessions.items():
        if u == uname:
            # Check if session has expired
            if id in session_timestamps:
                session_age = time.time() - session_timestamps[id]
                if session_age > _session_expiration_time:  # Session expired
                    remove_session(id)
                    continue
            return id
    return None


def cleanup_expired_sessions():
    """Remove all expired sessions"""
    current_time = time.time()
    expired_sessions = []

    for session_id, timestamp in session_timestamps.items():
        if current_time - timestamp > _session_expiration_time:
            expired_sessions.append(session_id)

    for session_id in expired_sessions:
        remove_session(session_id)

    return len(expired_sessions)


def get_active_sessions_count():
    """Get the number of active sessions"""
    cleanup_expired_sessions()  # Clean up first
    return len(sessions)


def get_session_info(session_id):
    """Get detailed information about a session"""
    if session_id not in sessions:
        return None

    current_time = time.time()
    created_at = session_timestamps.get(session_id, 0)
    last_activity = session_last_activity.get(session_id, 0)

    return {
        'user': sessions[session_id],
        'created_at': created_at,
        'last_activity': last_activity,
        'age_seconds': current_time - created_at,
        'idle_seconds': current_time - last_activity,
        'expires_in_seconds': _session_expiration_time - (current_time - created_at)
    }
