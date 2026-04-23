import os
import json
import pwd
import datetime
import config_loader


def _get_users_dir():
    """Returns the users config directory from config.conf, creating it if needed."""
    config = config_loader.load_config()
    base_dir = config.get('system', 'base_dir')
    users_dir = os.path.join(base_dir, 'users')
    os.makedirs(users_dir, exist_ok=True)
    return users_dir


def _get_base_dir():
    config = config_loader.load_config()
    return config.get('system', 'base_dir')


# ============================================================
# Admin management
# ============================================================

def _get_admin_file():
    return os.path.join(_get_base_dir(), 'admin.json')


def _load_admins():
    path = _get_admin_file()
    if os.path.isfile(path):
        with open(path, 'r') as f:
            return json.load(f)
    # Seed with default admin
    data = {"admins": ["jjrosat"]}
    _save_admins(data)
    return data


def _save_admins(data):
    path = _get_admin_file()
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def is_admin(username):
    data = _load_admins()
    return username in data.get('admins', [])


def set_admin(username, is_admin_flag):
    data = _load_admins()
    admins = data.get('admins', [])
    if is_admin_flag and username not in admins:
        admins.append(username)
    elif not is_admin_flag and username in admins:
        admins.remove(username)
    data['admins'] = admins
    _save_admins(data)


# ============================================================
# Activity log
# ============================================================

def _get_activity_log_file():
    return os.path.join(_get_base_dir(), 'activity.log')


def log_activity(username, action, details=""):
    """Appends an activity entry as a JSON line."""
    entry = {
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "username": username,
        "action": action,
        "details": details
    }
    path = _get_activity_log_file()
    with open(path, 'a') as f:
        f.write(json.dumps(entry) + '\n')


def get_activity_log(limit=500, username_filter=None):
    """Reads the last N activity log entries, optionally filtered by user."""
    path = _get_activity_log_file()
    if not os.path.isfile(path):
        return []
    entries = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                if username_filter and entry.get('username') != username_filter:
                    continue
                entries.append(entry)
            except json.JSONDecodeError:
                continue
    return entries[-limit:]


# ============================================================
# Projects management (user ↔ project assignments with status)
# ============================================================

_STATUS_COLORS = {
    'done': 'success',       # Green
    'not_ok': 'danger',      # Red
    'idle': 'warning',       # Yellow
    'wip': 'primary',        # Blue
}

_STATUS_LABELS = {
    'done': 'Done',
    'not_ok': 'Not OK',
    'idle': 'Idle',
    'wip': 'WIP',
}

# Master list of all known projects (display name → folder in /iDASREPO/PROJECTS/)
_DEFAULT_MASTER_PROJECTS = [
    {"name": "AVINOR",      "folder": "avinor"},
    {"name": "iCAS-LVNL",   "folder": "icas-lvnl"},
    {"name": "iSNS-LVNL",   "folder": "isns-lvnl"},
    {"name": "PANSA",        "folder": "pansa"},
    {"name": "FF-ICE",       "folder": "ffice"},
    {"name": "ROMATSA",      "folder": "romatsa"},
    {"name": "Nav-Canada",   "folder": "navcanada"},
    {"name": "NATS",         "folder": "nats"},
    {"name": "SKYNEX",       "folder": "skynex"},
    {"name": "IRTOS",        "folder": "irtos"},
    {"name": "UTM",          "folder": "utm"},
    {"name": "YAKARTA",      "folder": "yakarta"},
    {"name": "SACTA",        "folder": "sacta"},
]


def _get_master_projects_file():
    return os.path.join(_get_base_dir(), 'master_projects.json')


def _load_master_projects():
    path = _get_master_projects_file()
    if os.path.isfile(path):
        with open(path, 'r') as f:
            return json.load(f)
    # Seed with defaults
    _save_master_projects(_DEFAULT_MASTER_PROJECTS)
    return list(_DEFAULT_MASTER_PROJECTS)


def _save_master_projects(projects):
    path = _get_master_projects_file()
    with open(path, 'w') as f:
        json.dump(projects, f, indent=2)


def get_master_projects():
    """Returns the full master list of projects."""
    return _load_master_projects()


def add_master_project(name, folder):
    """Adds a new project to the master list."""
    projects = _load_master_projects()
    for p in projects:
        if p['name'].lower() == name.lower():
            return False, "Project already exists."
    projects.append({"name": name, "folder": folder})
    _save_master_projects(projects)
    return True, "OK"


def update_master_project(old_name, new_name, new_folder):
    """Updates a project in the master list."""
    projects = _load_master_projects()
    for p in projects:
        if p['name'].lower() == old_name.lower():
            # If renaming, check for duplicates
            if new_name.lower() != old_name.lower():
                for other in projects:
                    if other['name'].lower() == new_name.lower():
                        return False, "A project with that name already exists."
            # Also update in assignments
            if new_name != p['name']:
                _rename_project_in_assignments(p['name'], new_name)
            p['name'] = new_name
            p['folder'] = new_folder
            _save_master_projects(projects)
            return True, "OK"
    return False, "Project not found."


def delete_master_project(name):
    """Deletes a project from the master list and removes it from all user assignments."""
    projects = _load_master_projects()
    found = False
    new_projects = []
    for p in projects:
        if p['name'].lower() == name.lower():
            found = True
        else:
            new_projects.append(p)
    if not found:
        return False, "Project not found."
    _save_master_projects(new_projects)
    # Remove from all user assignments
    _remove_project_from_all_assignments(name)
    return True, "OK"


def _rename_project_in_assignments(old_name, new_name):
    """Renames a project in all user assignments."""
    data = _load_projects()
    for _uname, info in data.get('assignments', {}).items():
        for p in info.get('projects', []):
            if p['name'] == old_name:
                p['name'] = new_name
    _save_projects(data)


def _remove_project_from_all_assignments(name):
    """Removes a project from all user assignments."""
    data = _load_projects()
    for _uname, info in data.get('assignments', {}).items():
        info['projects'] = [p for p in info.get('projects', []) if p['name'].lower() != name.lower()]
    _save_projects(data)


def get_project_folder(project_name):
    """Returns the folder name for a project display name."""
    for p in _load_master_projects():
        if p['name'].lower() == project_name.lower():
            return p['folder']
    return project_name.lower()


def get_available_projects():
    """Returns projects from the master list that are NOT assigned to any user."""
    master = _load_master_projects()
    data = _load_projects()
    assigned = set()
    for _uname, info in data.get('assignments', {}).items():
        for p in info.get('projects', []):
            assigned.add(p['name'].lower())
    return [p for p in master if p['name'].lower() not in assigned]


def get_project_assignment(project_name):
    """Returns the username a project is assigned to, or None."""
    data = _load_projects()
    for uname, info in data.get('assignments', {}).items():
        for p in info.get('projects', []):
            if p['name'].lower() == project_name.lower():
                return uname, p.get('status', 'wip')
    return None, None


def _get_projects_file():
    return os.path.join(_get_base_dir(), 'projects.json')


def _load_projects():
    path = _get_projects_file()
    if os.path.isfile(path):
        with open(path, 'r') as f:
            return json.load(f)
    # Seed with initial managed users
    data = {
        "assignments": {
            "jjrosat": {
                "display_name": "Jibsan Toirac",
                "projects": [
                    {"name": "AVINOR", "status": "wip"},
                    {"name": "iCAS-LVNL", "status": "wip"},
                    {"name": "iSNS-LVNL", "status": "wip"}
                ]
            },
            "dsanchezca": {
                "display_name": "dsanchezca",
                "projects": []
            },
            "smoron": {
                "display_name": "smoron",
                "projects": []
            },
            "ipellicer": {
                "display_name": "ipellicer",
                "projects": []
            },
            "fggarcia": {
                "display_name": "fggarcia",
                "projects": []
            }
        }
    }
    _save_projects(data)
    return data


def _save_projects(data):
    path = _get_projects_file()
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


def get_all_projects():
    """Returns the full assignments dict."""
    return _load_projects().get('assignments', {})


def set_user_projects(username, projects, display_name=None):
    """Sets the project list for a user. projects = [{"name":"X","status":"wip"}, ...]"""
    data = _load_projects()
    if username not in data['assignments']:
        data['assignments'][username] = {"display_name": display_name or username, "projects": []}
    data['assignments'][username]['projects'] = projects
    if display_name is not None:
        data['assignments'][username]['display_name'] = display_name
    _save_projects(data)


def move_project(project_name, from_user, to_user):
    """Moves a project from one user to another, keeping its status."""
    data = _load_projects()
    assignments = data.get('assignments', {})

    # Find and remove from source
    project_data = None
    if from_user in assignments:
        projs = assignments[from_user]['projects']
        for i, p in enumerate(projs):
            if p['name'] == project_name:
                project_data = projs.pop(i)
                break

    if not project_data:
        return False, "Project not found on source user."

    # Add to destination
    if to_user not in assignments:
        dn = get_display_name(to_user)
        assignments[to_user] = {"display_name": dn, "projects": []}
    assignments[to_user]['projects'].append(project_data)
    _save_projects(data)
    return True, "OK"


def set_project_status(username, project_name, status):
    """Updates the status of a specific project for a user."""
    if status not in _STATUS_COLORS:
        return False, f"Invalid status. Must be one of: {', '.join(_STATUS_COLORS.keys())}"
    data = _load_projects()
    assignments = data.get('assignments', {})
    if username not in assignments:
        return False, "User not found."
    for p in assignments[username]['projects']:
        if p['name'] == project_name:
            p['status'] = status
            _save_projects(data)
            return True, "OK"
    return False, "Project not found."


def add_project(username, project_name, status='wip'):
    """Adds a new project to a user."""
    data = _load_projects()
    assignments = data.get('assignments', {})
    if username not in assignments:
        dn = get_display_name(username)
        assignments[username] = {"display_name": dn, "projects": []}
    # Check duplicate
    for p in assignments[username]['projects']:
        if p['name'].lower() == project_name.lower():
            return False, "Project already exists for this user."
    assignments[username]['projects'].append({"name": project_name, "status": status})
    _save_projects(data)
    return True, "OK"


def remove_project(username, project_name):
    """Removes a project from a user."""
    data = _load_projects()
    assignments = data.get('assignments', {})
    if username not in assignments:
        return False, "User not found."
    projs = assignments[username]['projects']
    for i, p in enumerate(projs):
        if p['name'] == project_name:
            projs.pop(i)
            _save_projects(data)
            return True, "OK"
    return False, "Project not found."


def remove_user_from_projects(username):
    """Removes a user completely from project assignments."""
    data = _load_projects()
    if username in data.get('assignments', {}):
        del data['assignments'][username]
        _save_projects(data)


def add_user_to_projects(username):
    """Adds a user to project assignments with empty project list."""
    data = _load_projects()
    if username not in data.get('assignments', {}):
        dn = get_display_name(username)
        data['assignments'][username] = {"display_name": dn, "projects": []}
        _save_projects(data)


def get_status_colors():
    return _STATUS_COLORS


def get_status_labels():
    return _STATUS_LABELS


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
