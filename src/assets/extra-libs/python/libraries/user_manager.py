import os
import json
import pwd
import config_loader


def _get_users_dir():
    """Returns the users config directory from config.conf, creating it if needed."""
    config = config_loader.load_config()
    base_dir = config.get('system', 'base_dir')
    users_dir = os.path.join(base_dir, 'users')
    os.makedirs(users_dir, exist_ok=True)
    return users_dir


def get_system_users():
    """Returns a list of real (non-system) usernames from the server.
    Filters to UID >= 1000 (normal users on Linux) and shells that are not nologin/false."""
    blocked_shells = ('/sbin/nologin', '/usr/sbin/nologin', '/bin/false', '/usr/bin/false')
    users = []
    for p in pwd.getpwall():
        if p.pw_uid >= 1000 and p.pw_shell not in blocked_shells:
            users.append(p.pw_name)
    return sorted(users)


def get_user_config(username):
    """Loads or initialises the JSON config for a user.
    Returns dict with at least: username, display_name."""
    users_dir = _get_users_dir()
    user_file = os.path.join(users_dir, f'{username}.json')

    if os.path.isfile(user_file):
        with open(user_file, 'r') as f:
            data = json.load(f)
        # Ensure required keys exist
        data.setdefault('username', username)
        data.setdefault('display_name', '')
        return data

    # First time: create default config
    data = {
        'username': username,
        'display_name': '',  # empty = use username
    }
    save_user_config(username, data)
    return data


def save_user_config(username, data):
    """Persists user config to disk."""
    users_dir = _get_users_dir()
    user_file = os.path.join(users_dir, f'{username}.json')
    data['username'] = username
    with open(user_file, 'w') as f:
        json.dump(data, f, indent=2)
    # Restrict permissions since file may contain credentials
    os.chmod(user_file, 0o600)


def get_display_name(username):
    """Returns the display name for a user. Falls back to username."""
    cfg = get_user_config(username)
    return cfg.get('display_name', '') or username


def validate_username(username):
    """Checks that a username exists on the system."""
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False
