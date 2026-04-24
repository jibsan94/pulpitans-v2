import os
import sys
import re
import json
import signal
import shutil
import tarfile
import hashlib
import secrets
import datetime
import subprocess
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libraries')
sys.path.insert(0, script_dir)

import git_manager
import path_finder
import make_yaml
import config_loader
import user_manager
import report_generator

# Global variable to store the running process
current_process = None


# ============================================================
# Password hashing helpers (PBKDF2-HMAC-SHA256)
# ============================================================

def _hash_password(password):
    """Return a salted PBKDF2-SHA256 hash of a plaintext password."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 200000)
    return salt + ':' + key.hex()


def _verify_password(password, stored_hash):
    """Verify a plaintext password against a stored salt:hash string."""
    try:
        salt, key_hex = stored_hash.split(':', 1)
        key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 200000)
        return secrets.compare_digest(key.hex(), key_hex)
    except Exception:
        return False


def _get_auth_method():
    """Return the configured auth method: 'system', 'database', or 'sso'."""
    return _get_system_settings().get('auth', {}).get('method', 'system')


def _db_get_password_hash(username):
    """Fetch the stored password_hash for a user from the DB. Returns '' if not found."""
    conn = _db_connect()
    if not conn:
        return ''
    try:
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE username=%s LIMIT 1", (username,))
        row = cur.fetchone()
        return (row['password_hash'] or '') if row else ''
    except Exception:
        return ''
    finally:
        conn.close()


def _db_set_password_hash(username, password_hash):
    """Persist a hashed password for a user in the DB."""
    conn = _db_connect()
    if not conn:
        return
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash=%s WHERE username=%s",
                    (password_hash, username))
    except Exception:
        pass
    finally:
        conn.close()


# ============================================================
# Auth / User endpoints
# ============================================================

@app.route('/auth/users')
def auth_list_users():
    """Return the list of managed users (those in projects.json) available for login."""
    try:
        if _storage_is_db():
            assignments = _db_get_all_assignments()
        else:
            assignments = user_manager.get_all_projects()
        users = sorted(assignments.keys())
        return jsonify({"success": True, "users": users})
    except Exception as e:
        return jsonify({"success": True, "users": []})


@app.route('/auth/login', methods=['POST'])
def auth_login():
    """Validate username + password and return profile.
    - auth_method=system: authenticate via PAM; sync hash to DB if DB mode.
    - auth_method=database: verify against DB password_hash.
      If user has no hash yet (new DB user), returns needs_password=True.
    """
    try:
        data = request.get_json()
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '')

        if not username:
            return jsonify({"success": False, "error": "Username is required."})
        if not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            return jsonify({"success": False, "error": "Invalid username."})

        auth_method = _get_auth_method()

        # For system auth, user must exist on the OS. DB-only users may not be OS users.
        if not (auth_method == 'database' and _storage_is_db()):
            if not user_manager.validate_username(username):
                return jsonify({"success": False, "error": f"User '{username}' does not exist on this system."})

        # Check user is in the managed list
        if _storage_is_db():
            assignments = _db_get_all_assignments()
        else:
            assignments = user_manager.get_all_projects()
        if username not in assignments:
            return jsonify({"success": False, "error": "User is not enabled. Contact an administrator."})

        if auth_method == 'database' and _storage_is_db():
            # --- Database authentication ---
            stored_hash = _db_get_password_hash(username)
            is_os_user = user_manager.validate_username(username)
            if not stored_hash and not is_os_user:
                # DB-only user with no password — must go through initial-password flow
                return jsonify({"success": False, "needs_password": True, "username": username})
            if not stored_hash and is_os_user:
                # OS user with no DB hash yet — fall through to PAM and sync
                if not password:
                    return jsonify({"success": False, "error": "Password is required."})
                import pam
                p = pam.pam()
                if not p.authenticate(username, password):
                    return jsonify({"success": False, "error": "Incorrect password."})
                _db_set_password_hash(username, _hash_password(password))
            else:
                # Has a DB hash — verify against it
                if not password:
                    return jsonify({"success": False, "error": "Password is required."})
                if not _verify_password(password, stored_hash):
                    return jsonify({"success": False, "error": "Incorrect password."})
        else:
            # --- System (PAM) authentication ---
            if not password:
                return jsonify({"success": False, "error": "Password is required."})
            import pam
            p = pam.pam()
            if not p.authenticate(username, password):
                return jsonify({"success": False, "error": "Incorrect password."})
            # Keep DB hash in sync with system password
            if _storage_is_db():
                _db_set_password_hash(username, _hash_password(password))

        if _storage_is_db():
            cfg = _db_get_user_config(username)
            is_admin = _db_is_admin(username)
        else:
            cfg = user_manager.get_user_config(username)
            is_admin = user_manager.is_admin(username)
        user_manager.log_activity(username, 'login', 'User logged in')

        return jsonify({
            "success": True,
            "username": username,
            "display_name": cfg.get('display_name', '') or username,
            "is_admin": is_admin
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/auth/set-initial-password', methods=['POST'])
def auth_set_initial_password():
    """Set the first password for a new DB-mode user who has no password yet.
    Security: only works if the user currently has NO password_hash in the DB.
    """
    try:
        data = request.get_json()
        username = (data.get('username') or '').strip()
        password = (data.get('password') or '')

        if not username or not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            return jsonify({"success": False, "error": "Invalid username."})

        if not (_get_auth_method() == 'database' and _storage_is_db()):
            return jsonify({"success": False, "error": "Initial password setup is only available in Database auth mode."})

        # Security: reject if a hash already exists (this is not a password-reset endpoint)
        if _db_get_password_hash(username):
            return jsonify({"success": False, "error": "Password already set. Use Change Password instead."})

        # Verify user is in the managed list
        assignments = _db_get_all_assignments()
        if username not in assignments:
            return jsonify({"success": False, "error": "User is not enabled."})

        # Validate password requirements
        if not password or len(password) < 4:
            return jsonify({"success": False, "error": "Password must be at least 4 characters."})
        if not re.search(r'[0-9]', password):
            return jsonify({"success": False, "error": "Password must contain at least one number."})
        if not re.search(r'[A-Z]', password):
            return jsonify({"success": False, "error": "Password must contain at least one uppercase letter."})
        if not re.search(r'[.,&@#!]', password):
            return jsonify({"success": False, "error": "Password must contain at least one special character (. , & @ # !)."})

        _db_set_password_hash(username, _hash_password(password))

        cfg = _db_get_user_config(username)
        user_manager.log_activity(username, 'set_initial_password', 'User set initial password')

        return jsonify({
            "success": True,
            "username": username,
            "display_name": cfg.get('display_name', '') or username,
            "is_admin": _db_is_admin(username)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/auth/profile', methods=['GET'])
def auth_get_profile():
    """Get user profile. Username comes from query param (set by cookie on client)."""
    try:
        username = request.args.get('username', '').strip()
        if not username or not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            return jsonify({"success": False, "error": "Invalid username."})

        if _storage_is_db():
            cfg = _db_get_user_config(username)
            cfg['is_admin'] = _db_is_admin(username)
        else:
            cfg = user_manager.get_user_config(username)
            cfg['is_admin'] = user_manager.is_admin(username)
        return jsonify({"success": True, "profile": cfg})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/auth/profile', methods=['POST'])
def auth_update_profile():
    """Update user profile (display_name, etc.)."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        display_name = data.get('display_name', '').strip()

        if not username or not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            return jsonify({"success": False, "error": "Invalid username."})

        if _storage_is_db():
            cfg = _db_get_user_config(username)
        else:
            cfg = user_manager.get_user_config(username)
        cfg['display_name'] = display_name

        # BitBucket credentials (optional)
        if 'bitbucket_username' in data:
            cfg['bitbucket_username'] = data['bitbucket_username'].strip()
        if 'bitbucket_password' in data:
            cfg['bitbucket_password'] = data['bitbucket_password']

        if _storage_is_db():
            _db_save_user_config(username, cfg)
        else:
            user_manager.save_user_config(username, cfg)

        return jsonify({
            "success": True,
            "display_name": display_name or username
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/auth/method', methods=['GET'])
def auth_get_method():
    """Return the current auth method so the frontend can show/hide password change."""
    return jsonify({"success": True, "method": _get_auth_method()})


@app.route('/auth/needs-password', methods=['GET'])
def auth_needs_password():
    """Check whether a user needs to set their initial password (DB auth, no hash yet).
    Returns needs_password=True only if: DB mode is active, auth_method is database,
    the user exists in the managed list, and has no password hash."""
    username = request.args.get('username', '').strip()
    if not username or not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
        return jsonify({"needs_password": False})
    if not (_get_auth_method() == 'database' and _storage_is_db()):
        return jsonify({"needs_password": False})
    assignments = _db_get_all_assignments()
    if username not in assignments:
        return jsonify({"needs_password": False})
    stored_hash = _db_get_password_hash(username)
    if stored_hash:
        return jsonify({"needs_password": False})
    # Only DB-only users (no OS account) need the initial-password flow.
    # OS users can authenticate via PAM and their hash will be synced.
    is_os_user = user_manager.validate_username(username)
    return jsonify({"needs_password": not is_os_user})


@app.route('/auth/change-password', methods=['POST'])
def auth_change_password():
    """Change the user's DB password. Only allowed when auth_method='database' and DB mode is on."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not username or not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            return jsonify({"success": False, "error": "Invalid username."})

        if _get_auth_method() != 'database':
            return jsonify({"success": False, "error": "Password change is only available in Database auth mode."})

        if not _storage_is_db():
            return jsonify({"success": False, "error": "Database storage is required to change passwords."})

        if not new_password or len(new_password) < 6:
            return jsonify({"success": False, "error": "New password must be at least 6 characters."})

        stored_hash = _db_get_password_hash(username)
        if stored_hash:
            if not _verify_password(current_password, stored_hash):
                return jsonify({"success": False, "error": "Current password is incorrect."})
        else:
            # No hash yet — verify via PAM before allowing change
            import pam
            p = pam.pam()
            if not p.authenticate(username, current_password):
                return jsonify({"success": False, "error": "Current password is incorrect."})

        _db_set_password_hash(username, _hash_password(new_password))
        user_manager.log_activity(username, 'change_password', 'User changed their password')
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


def _get_user_picture_paths(username):
    """Returns (data_path, mime_path) for persisting a user's profile picture on disk."""
    users_dir = os.path.join(user_manager._get_base_dir(), 'users')
    os.makedirs(users_dir, exist_ok=True)
    return (
        os.path.join(users_dir, f'{username}_pic'),
        os.path.join(users_dir, f'{username}_pic.mime')
    )


@app.route('/auth/profile-picture/<username>', methods=['GET'])
def auth_get_profile_picture(username):
    """Serve the user's profile picture. Checks filesystem first, then DB, then default."""
    from flask import send_file
    import io
    if not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
        return ('', 400)
    # 1) Filesystem (works without DB, no Deploy required)
    data_path, mime_path = _get_user_picture_paths(username)
    if os.path.isfile(data_path):
        mime = 'image/jpeg'
        if os.path.isfile(mime_path):
            with open(mime_path, 'r') as fp:
                mime = fp.read().strip() or 'image/jpeg'
        return send_file(data_path, mimetype=mime)
    # 2) DB (if deployed and enabled)
    if _storage_is_db():
        conn = _db_connect()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute(
                    "SELECT up.picture_data, up.mime_type FROM user_pictures up "
                    "JOIN users u ON u.id = up.user_id "
                    "WHERE u.username = %s LIMIT 1",
                    (username,)
                )
                row = cur.fetchone()
                if row and row['picture_data']:
                    return send_file(
                        io.BytesIO(row['picture_data']),
                        mimetype=row['mime_type'] or 'image/jpeg',
                        as_attachment=False
                    )
            except Exception:
                pass
            finally:
                conn.close()
    # 3) Default static picture
    default_pic = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               '..', '..', 'images', 'users', 'profile-pic.jpg')
    if os.path.isfile(default_pic):
        return send_file(default_pic, mimetype='image/jpeg')
    return ('', 404)


@app.route('/auth/profile-picture', methods=['POST'])
def auth_upload_profile_picture():
    """Upload a new profile picture. Always saves to filesystem; also saves to DB if available."""
    username = request.form.get('username', '').strip()
    if not username or not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
        return jsonify({"success": False, "error": "Invalid username."})
    if 'picture' not in request.files:
        return jsonify({"success": False, "error": "No file provided."})
    f = request.files['picture']
    if not f or f.filename == '':
        return jsonify({"success": False, "error": "No file selected."})
    mime = f.content_type or 'image/jpeg'
    if not mime.startswith('image/'):
        return jsonify({"success": False, "error": "Only image files are allowed."})
    data = f.read()
    if len(data) > 5 * 1024 * 1024:
        return jsonify({"success": False, "error": "Image must be smaller than 5 MB."})
    # 1) Always save to filesystem (no DB or Deploy needed)
    try:
        data_path, mime_path = _get_user_picture_paths(username)
        with open(data_path, 'wb') as fp:
            fp.write(data)
        with open(mime_path, 'w') as fp:
            fp.write(mime)
    except Exception as e:
        return jsonify({"success": False, "error": "Could not save picture: " + str(e)})
    # 2) Also save to DB if available (best-effort, won't fail the request)
    if _storage_is_db():
        conn = _db_connect()
        if conn:
            try:
                cur = conn.cursor()
                cur.execute("INSERT IGNORE INTO users (username) VALUES (%s)", (username,))
                cur.execute("SELECT id FROM users WHERE username=%s LIMIT 1", (username,))
                row = cur.fetchone()
                if row:
                    cur.execute(
                        "INSERT INTO user_pictures (user_id, picture_data, mime_type) VALUES (%s, %s, %s) "
                        "ON DUPLICATE KEY UPDATE picture_data=VALUES(picture_data), mime_type=VALUES(mime_type)",
                        (row['id'], data, mime)
                    )
            except Exception:
                pass  # DB table may not exist yet — filesystem save is enough
            finally:
                conn.close()
    user_manager.log_activity(username, 'upload_picture', 'User updated profile picture')
    return jsonify({"success": True})


@app.route('/search-roles')
def search_roles():
    try:
        config = config_loader.load_config()
        base_route  = config['search']['base_route']
        folder_name = config['search']['folder_name']

        # Scope search to the logged-in user's home directory
        username = request.args.get('username', '').strip()
        if username and re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            user_home = os.path.join(base_route, username)
            if os.path.isdir(user_home):
                base_route = user_home

        routes = path_finder.search_folder(folder_name, base_route)
        return jsonify({
            "routes": routes,
            "error": ""
        })
    except Exception as e:
        return jsonify({
            "routes": [],
            "error": str(e)
        })

@app.route('/generate-playbook', methods=['POST'])
def generate_playbook():
    try:
        data = request.get_json()
        selected_role = data.get('role', '')

        if not selected_role:
            return jsonify({"success": False, "error": "No role selected."})

        config = config_loader.load_config()
        output_path = os.path.join(config['build']['output_path'], 'build.yaml')

        form_data = {
            'branch_name':       data.get('branch_name', ''),
            'gitrepo_local_dir': data.get('gitrepo_local_dir', ''),
            'mkbuild_project':   data.get('mkbuild_project', ''),
            'gitrepo_update':    data.get('gitrepo_update', 'disabled'),
            'gitrepo_checkitc':  data.get('gitrepo_checkitc', 'disabled'),
            'gitrepo_git2cc':    data.get('gitrepo_git2cc', 'disabled'),
            'idasrpm_build':     data.get('idasrpm_build', 'disabled'),
            'idasrepo_build':    data.get('idasrepo_build', 'disabled'),
            'idasbuild_build':   data.get('idasbuild_build', 'disabled'),
        }

        make_yaml.generate_build_yaml(selected_role, output_path, form_data)

        return jsonify({"success": True, "error": "", "path": output_path})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/check-playbook')
def check_playbook():
    try:
        config = config_loader.load_config()
        output_path = os.path.join(config['build']['output_path'], 'build.yaml')
        exists = os.path.exists(output_path)
        return jsonify({
            "exists": exists,
            "path": output_path
        })
    except Exception as e:
        return jsonify({
            "exists": False,
            "path": "",
            "error": str(e)
        })

@app.route('/run-build')
def run_build():
    global current_process
    try:
        config = config_loader.load_config()
        playbook_path = os.path.join(config['build']['output_path'], 'build.yaml')

        if not os.path.exists(playbook_path):
            return jsonify({"error": "Playbook not found. Generate it first."}), 404

        def generate():
            global current_process
            env = os.environ.copy()
            env['ANSIBLE_FORCE_COLOR'] = '1'

            current_process = subprocess.Popen(
                ['script', '-qfc', f'ansible-playbook {playbook_path}', '/dev/null'],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                env=env
            )
            for line in iter(current_process.stdout.readline, ''):
                yield f"data: {line}\n\n"
            current_process.stdout.close()
            current_process.wait()
            current_process = None
            yield "data: __END__\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no'
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/stop-build', methods=['POST'])
def stop_build():
    global current_process
    try:
        if current_process and current_process.poll() is None:
            current_process.terminate()
            current_process = None
            return jsonify({"success": True, "message": "Build stopped."})
        else:
            return jsonify({"success": False, "message": "No build is currently running."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ============================================================
# Background Build Management (mkbuild)
# ============================================================

def _get_mkbuild_paths():
    """Returns (make_build_path, make_build_logs) from config."""
    config = config_loader.load_config()
    base_dir = config.get('system', 'base_dir')
    make_build_path = os.path.join(base_dir, 'make_build_pid')
    make_build_logs = os.path.join(make_build_path, 'logs')
    os.makedirs(make_build_path, exist_ok=True)
    os.makedirs(make_build_logs, exist_ok=True)
    return make_build_path, make_build_logs

@app.route('/mkbuild/start', methods=['POST'])
def mkbuild_start():
    """Start a build as a background process."""
    try:
        data = request.get_json()
        selected_role = data.get('role', '')
        branch_name = data.get('branch_name', '')

        if not selected_role:
            return jsonify({"success": False, "error": "No role selected."})
        if not branch_name:
            return jsonify({"success": False, "error": "Branch name is required."})

        # Generate unique build ID
        now = datetime.datetime.now()
        date_str = now.strftime('%Y%m%d_%H%M%S')
        safe_branch = re.sub(r'[^a-zA-Z0-9_-]', '_', branch_name)
        build_id = f"mkbuild_{safe_branch}_{date_str}"

        # Get paths
        make_build_path, make_build_logs = _get_mkbuild_paths()

        # Generate playbook to unique path
        config = config_loader.load_config()
        playbook_path = os.path.join(config['build']['output_path'], f'{build_id}.yaml')

        form_data = {
            'branch_name':       branch_name,
            'gitrepo_local_dir': data.get('gitrepo_local_dir', ''),
            'mkbuild_project':   data.get('mkbuild_project', ''),
            'gitrepo_update':    data.get('gitrepo_update', 'disabled'),
            'gitrepo_checkitc':  data.get('gitrepo_checkitc', 'disabled'),
            'gitrepo_git2cc':    data.get('gitrepo_git2cc', 'disabled'),
            'idasrpm_build':     data.get('idasrpm_build', 'disabled'),
            'idasrepo_build':    data.get('idasrepo_build', 'disabled'),
            'idasbuild_build':   data.get('idasbuild_build', 'disabled'),
        }

        make_yaml.generate_build_yaml(selected_role, playbook_path, form_data)

        # Build ansible command with optional git credentials
        git_username = data.get('git_username', '')
        git_password = data.get('git_password', '')

        extra_vars_file = None
        cmd_parts = ['ansible-playbook', playbook_path]

        if git_username and git_password:
            from urllib.parse import quote as url_quote
            base_url = config.get('system', 'repo_url').rstrip('/')
            auth_url = base_url.replace('https://', f'https://{url_quote(git_username, safe="")}:{url_quote(git_password, safe="")}@')
            # Write extra vars to a temp file to avoid exposing creds in ps
            extra_vars_file = os.path.join(make_build_path, f'{build_id}_vars.json')
            with open(extra_vars_file, 'w') as vf:
                json.dump({"idas_tool_mkbuild_gitrepo_remote": auth_url}, vf)
            os.chmod(extra_vars_file, 0o600)
            cmd_parts += ['-e', f'@{extra_vars_file}']

        # Start background process
        log_path = os.path.join(make_build_logs, f'{build_id}.log')
        log_file = open(log_path, 'w')

        env = os.environ.copy()
        env['ANSIBLE_FORCE_COLOR'] = '1'

        ansible_cmd = ' '.join(cmd_parts)
        proc = subprocess.Popen(
            ['script', '-qfc', ansible_cmd, '/dev/null'],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True
        )

        # Create tracking JSON
        owner = data.get('owner', '')
        tracking = {
            "id": build_id,
            "branch": branch_name,
            "role": selected_role,
            "pid": proc.pid,
            "log_path": log_path,
            "playbook_path": playbook_path,
            "started_at": now.strftime('%Y-%m-%d %H:%M:%S'),
            "status": "running",
            "owner": owner
        }

        json_path = os.path.join(make_build_path, f'{build_id}.json')
        with open(json_path, 'w') as f:
            json.dump(tracking, f, indent=2)

        # Log activity
        user_manager.log_activity(owner or 'unknown', 'mkbuild_start',
            f'Started build {build_id} on branch {branch_name} with role {selected_role}')

        return jsonify({"success": True, "build_id": build_id, "pid": proc.pid})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/mkbuild/list')
def mkbuild_list():
    """List all background builds, checking PID status."""
    try:
        make_build_path, _ = _get_mkbuild_paths()
        builds = []

        for fname in sorted(os.listdir(make_build_path), reverse=True):
            if not fname.endswith('.json') or fname.endswith('_vars.json'):
                continue
            json_path = os.path.join(make_build_path, fname)
            try:
                with open(json_path, 'r') as f:
                    build = json.load(f)

                # Check if process is still running
                pid = build.get('pid')
                if pid and build.get('status') == 'running':
                    try:
                        os.kill(pid, 0)  # signal 0 = check if alive
                    except OSError:
                        build['status'] = 'finished'
                        with open(json_path, 'w') as fw:
                            json.dump(build, fw, indent=2)

                builds.append(build)
            except (json.JSONDecodeError, IOError):
                continue

        return jsonify({"success": True, "builds": builds})

    except Exception as e:
        return jsonify({"success": False, "builds": [], "error": str(e)})

@app.route('/mkbuild/stop', methods=['POST'])
def mkbuild_stop():
    """Stop a background build by build_id."""
    try:
        data = request.get_json()
        build_id = data.get('build_id', '')

        if not build_id:
            return jsonify({"success": False, "error": "build_id is required."})

        if not re.match(r'^mkbuild_[a-zA-Z0-9_-]+$', build_id):
            return jsonify({"success": False, "error": "Invalid build ID."})

        make_build_path, _ = _get_mkbuild_paths()
        json_path = os.path.join(make_build_path, f'{build_id}.json')

        if not os.path.exists(json_path):
            return jsonify({"success": False, "error": "Build not found."})

        with open(json_path, 'r') as f:
            build = json.load(f)

        pid = build.get('pid')
        if not pid:
            return jsonify({"success": False, "error": "No PID found."})

        try:
            os.kill(pid, signal.SIGTERM)
            build['status'] = 'stopped'
            with open(json_path, 'w') as fw:
                json.dump(build, fw, indent=2)
            return jsonify({"success": True, "message": f"Build {build_id} stopped."})
        except OSError:
            build['status'] = 'finished'
            with open(json_path, 'w') as fw:
                json.dump(build, fw, indent=2)
            return jsonify({"success": False, "error": "Process is not running."})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/mkbuild/log/<build_id>')
def mkbuild_log(build_id):
    """Get the log content for a build."""
    try:
        if not re.match(r'^mkbuild_[a-zA-Z0-9_-]+$', build_id):
            return jsonify({"success": False, "error": "Invalid build ID."})

        make_build_path, _ = _get_mkbuild_paths()
        json_path = os.path.join(make_build_path, f'{build_id}.json')

        if not os.path.exists(json_path):
            return jsonify({"success": False, "error": "Build not found."})

        with open(json_path, 'r') as f:
            build = json.load(f)

        log_path = build.get('log_path', '')
        if not log_path or not os.path.exists(log_path):
            return jsonify({"success": True, "log": "Log file not found yet.", "status": build.get('status', 'unknown')})

        tail = request.args.get('tail', type=int, default=0)

        with open(log_path, 'r', errors='replace') as f:
            if tail > 0:
                lines = f.readlines()
                content = ''.join(lines[-tail:])
            else:
                content = f.read()

        # Check PID status
        pid = build.get('pid')
        status = build.get('status', 'unknown')
        if pid and status == 'running':
            try:
                os.kill(pid, 0)
            except OSError:
                status = 'finished'
                build['status'] = status
                with open(json_path, 'w') as fw:
                    json.dump(build, fw, indent=2)

        return jsonify({"success": True, "log": content, "status": status})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/mkbuild/delete', methods=['POST'])
def mkbuild_delete():
    """Delete a build tracking file and its log."""
    try:
        data = request.get_json()
        build_id = data.get('build_id', '')

        if not build_id:
            return jsonify({"success": False, "error": "build_id is required."})

        if not re.match(r'^mkbuild_[a-zA-Z0-9_-]+$', build_id):
            return jsonify({"success": False, "error": "Invalid build ID."})

        make_build_path, _ = _get_mkbuild_paths()
        json_path = os.path.join(make_build_path, f'{build_id}.json')

        if not os.path.exists(json_path):
            return jsonify({"success": False, "error": "Build not found."})

        with open(json_path, 'r') as f:
            build = json.load(f)

        # Don't delete running builds
        pid = build.get('pid')
        if pid:
            try:
                os.kill(pid, 0)
                return jsonify({"success": False, "error": "Cannot delete a running build. Stop it first."})
            except OSError:
                pass

        # Delete log file
        log_path = build.get('log_path', '')
        if log_path and os.path.exists(log_path):
            os.remove(log_path)

        # Delete playbook
        playbook_path = build.get('playbook_path', '')
        if playbook_path and os.path.exists(playbook_path):
            os.remove(playbook_path)

        # Delete extra vars file (contains credentials)
        vars_file = os.path.join(make_build_path, f'{build_id}_vars.json')
        if os.path.exists(vars_file):
            os.remove(vars_file)

        # Delete JSON
        os.remove(json_path)

        return jsonify({"success": True, "message": f"Build {build_id} deleted."})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/get-config')
def get_config():
    try:
        config = config_loader.load_config()
        return jsonify({
            "message_timeout": int(config['ui']['message_timeout']),
            "repo_url": config.get('system', 'repo_url')
        })
    except Exception as e:
        return jsonify({"message_timeout": 10, "repo_url": ""})

@app.route('/git/download-repo', methods=['POST'])
def download_repo():
    try:
        data     = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')

        if not username or not password:
            return jsonify({"success": False, "error": "Username and password are required."})

        config    = config_loader.load_config()
        repo_url  = config.get('system', 'repo_url')
        repo_path = git_manager.get_repo_path(config)

        # If repo already exists, skip clone
        if os.path.exists(repo_path):
            return jsonify({"success": False, "error": f"Repo already exists at {repo_path}. Use Update Repo instead."})

        result = git_manager.clone_repo(repo_url, repo_path, username, password)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/git/update-repo', methods=['POST'])
def update_repo():
    try:
        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        result    = git_manager.update_repo(repo_path)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/git/get-branches')
def get_branches():
    try:
        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        result    = git_manager.get_branches(repo_path)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "branches": [], "error": str(e)})

@app.route('/git/get-commits')
def get_commits():
    try:
        branch    = request.args.get('branch', '')
        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        result    = git_manager.get_commits(repo_path, branch)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "commits": [], "error": str(e)})

@app.route('/git/apply-tag', methods=['POST'])
def apply_tag():
    try:
        data        = request.get_json()
        tag_name    = data.get('tag_name', '')
        commit_hash = data.get('commit_hash', '')

        if not tag_name or not commit_hash:
            return jsonify({"success": False, "error": "Tag name and commit are required."})

        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        result    = git_manager.apply_tag(repo_path, tag_name, commit_hash)
        return jsonify(result)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/git/get-tags')
def git_get_tags():
    try:
        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        result    = git_manager.get_tags(repo_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "tags": [], "error": str(e)})

@app.route('/git/delete-tag', methods=['POST'])
def git_delete_tag():
    try:
        data     = request.get_json()
        tag_name = data.get('tag_name', '').strip()
        if not tag_name:
            return jsonify({"success": False, "error": "Tag name is required."})
        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        result    = git_manager.delete_tag(repo_path, tag_name)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    
# When opening a browser and type http://localhost:5000/git/debug-path, it will show the repo path and if it exists or not. This is useful for debugging config issues.
#######################################################################################################################################################################
@app.route('/git/debug-path')
def debug_path():
    config = config_loader.load_config()
    repo_path = git_manager.get_repo_path(config)
    return jsonify({
        "repo_path": repo_path,
        "exists": os.path.exists(repo_path)
    })
# This can be deleted, it's just for debugging purposes to check if the path is correct and if the repo exists.
#######################################################################################################################################################################
import builds_scanner

@app.route('/dashboard/builds')
def dashboard_builds():
    try:
        data = builds_scanner.scan_builds()

        # Build engineers from projects.json (managed users) instead of hardcoded ENGINEER_PROJECTS
        assignments = user_manager.get_all_projects()
        engineers = {}
        for username, info in assignments.items():
            total_builds = 0
            total_size_bytes = 0
            latest_build = "--"
            latest_mtime = 0

            for proj in info.get('projects', []):
                folder = user_manager.get_project_folder(proj['name'])
                matched = data["projects"].get(folder)
                if matched:
                    total_builds += matched["total_builds"]
                    total_size_bytes += matched["total_size_bytes"]
                    mtime = matched.get("latest_mtime", 0)
                    if mtime > latest_mtime:
                        latest_mtime = mtime
                        latest_build = matched["latest_build"]

            display_name = user_manager.get_display_name(username)
            engineers[display_name] = {
                "username": username,
                "projects": [p['name'] for p in info.get('projects', [])],
                "total_builds": total_builds,
                "total_size": builds_scanner.format_size(total_size_bytes),
                "total_size_bytes": total_size_bytes,
                "latest_build": latest_build
            }

        return jsonify({
            "success": True,
            "summary": {
                "total_builds":    data["total_builds"],
                "total_size":      data["total_size"],
                "active_projects": data["active_projects"],
                "latest_build":    data["latest_build"]
            },
            "projects":  data["projects"],
            "engineers": engineers
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/dashboard/system')
def dashboard_system():
    """Returns real-time memory and /iDASREPO disk usage."""
    try:
        settings = _get_system_settings()

        if settings['mode'] == 'remote' and settings.get('remote_ip'):
            return _dashboard_system_remote(settings['remote_ip'], settings.get('ssh_user', 'root'))

        # --- Local: Memory ---
        with open('/proc/meminfo', 'r') as f:
            meminfo = {}
            for line in f:
                parts = line.split()
                meminfo[parts[0].rstrip(':')] = int(parts[1])  # kB
        mem_total = meminfo['MemTotal']
        mem_available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
        mem_used = mem_total - mem_available
        mem_percent = round(mem_used / mem_total * 100, 1) if mem_total else 0

        def fmt_gb(kb):
            return f"{kb / 1048576:.1f} GB"

        # --- Local: Disk /iDASREPO ---
        disk = {"total": "--", "used": "--", "free": "--", "percent": 0}
        try:
            st = os.statvfs('/iDASREPO')
            d_total = st.f_frsize * st.f_blocks
            d_free = st.f_frsize * st.f_bavail
            d_used = d_total - d_free
            d_pct = round(d_used / d_total * 100, 1) if d_total else 0
            def fmt_bytes(b):
                if b >= 1099511627776:
                    return f"{b / 1099511627776:.1f}T"
                return f"{b / 1073741824:.0f}G"
            disk = {
                "total": fmt_bytes(d_total),
                "used": fmt_bytes(d_used),
                "free": fmt_bytes(d_free),
                "percent": d_pct
            }
        except OSError:
            pass

        return jsonify({
            "success": True,
            "memory": {
                "total": fmt_gb(mem_total),
                "used": fmt_gb(mem_used),
                "free": fmt_gb(mem_available),
                "percent": mem_percent
            },
            "disk": disk
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


def _dashboard_system_remote(remote_ip, ssh_user):
    """Fetch memory and disk info from remote host via SSH."""
    try:
        out = _run_remote(['cat', '/proc/meminfo'], remote_ip, ssh_user)
        meminfo = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                meminfo[parts[0].rstrip(':')] = int(parts[1])
        mem_total = meminfo.get('MemTotal', 0)
        mem_available = meminfo.get('MemAvailable', meminfo.get('MemFree', 0))
        mem_used = mem_total - mem_available
        mem_percent = round(mem_used / mem_total * 100, 1) if mem_total else 0

        def fmt_gb(kb):
            return '{:.1f} GB'.format(kb / 1048576)

        disk = {"total": "--", "used": "--", "free": "--", "percent": 0}
        try:
            df_out = _run_remote(['df', '-B1', '/iDASREPO'], remote_ip, ssh_user)
            df_lines = df_out.strip().splitlines()
            if len(df_lines) >= 2:
                parts = df_lines[1].split()
                d_total = int(parts[1])
                d_used = int(parts[2])
                d_free = int(parts[3])
                d_pct = round(d_used / d_total * 100, 1) if d_total else 0
                def fmt_bytes(b):
                    if b >= 1099511627776:
                        return '{:.1f}T'.format(b / 1099511627776)
                    return '{:.0f}G'.format(b / 1073741824)
                disk = {"total": fmt_bytes(d_total), "used": fmt_bytes(d_used),
                        "free": fmt_bytes(d_free), "percent": d_pct}
        except Exception:
            pass

        return jsonify({
            "success": True,
            "memory": {"total": fmt_gb(mem_total), "used": fmt_gb(mem_used),
                       "free": fmt_gb(mem_available), "percent": mem_percent},
            "disk": disk
        })
    except Exception as e:
        return jsonify({"success": False, "error": "Remote: " + str(e)})

# All above this is endpoints, do not delete the lines below

# ============================================================
# SRN endpoints
# ============================================================
_SRN_SOURCE_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'srn')
)
_SRN_CONFIG_PATH = os.path.join(_SRN_SOURCE_DIR, 'config.cfg')

def _get_srn_paths(config):
    """Resolves srn_base_dir / srn_pandoc_dir / srn_build_dir from config.conf.
    Cross-section interpolation is not natively supported by configparser,
    so we build the paths manually from [system] base_dir."""
    base_dir   = config.get('system', 'base_dir')
    srn_base   = os.path.join(base_dir, 'srn')
    srn_pandoc = os.path.join(srn_base, 'pandoc')
    srn_build  = os.path.join(srn_base, 'build')
    return srn_base, srn_pandoc, srn_build

def _get_srn_pid_paths():
    """Returns (srn_pid_dir, srn_pid_logs) from config."""
    config = config_loader.load_config()
    base_dir = config.get('system', 'base_dir')
    srn_pid_dir  = os.path.join(base_dir, 'srn_pid')
    srn_pid_logs = os.path.join(srn_pid_dir, 'logs')
    os.makedirs(srn_pid_dir, exist_ok=True)
    os.makedirs(srn_pid_logs, exist_ok=True)
    return srn_pid_dir, srn_pid_logs

def _safe_tar_extract(tar, dest):
    """Extract tarball with path-traversal protection (zip-slip guard)."""
    real_dest = os.path.realpath(dest)
    for member in tar.getmembers():
        member_path = os.path.realpath(os.path.join(dest, member.name))
        if not member_path.startswith(real_dest + os.sep) and member_path != real_dest:
            raise ValueError(f'Unsafe path in tarball: {member.name}')
    tar.extractall(path=dest)

def _parse_srn_config(path):
    """Parses shell-style KEY="VALUE" config file used by SRN scripts"""
    result = {}
    pattern = re.compile(r'^(\w+)\s*=\s*"?([^"]*)"?\s*$')
    try:
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('#') or not line:
                    continue
                m = pattern.match(line)
                if m:
                    result[m.group(1)] = m.group(2)
    except FileNotFoundError:
        pass
    return result

def _write_srn_config(path, data):
    """Updates KEY="VALUE" pairs in the config file while preserving comments"""
    try:
        with open(path, 'r') as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []
    new_lines = []
    for line in lines:
        m = re.match(r'^(\w+)\s*=', line.strip())
        if m and m.group(1) in data:
            new_lines.append(f'{m.group(1)}="{data[m.group(1)]}"\n')
        else:
            new_lines.append(line)
    with open(path, 'w') as f:
        f.writelines(new_lines)

@app.route('/srn/config')
def srn_get_config():
    try:
        cfg = _parse_srn_config(_SRN_CONFIG_PATH)
        return jsonify({
            "success": True,
            "tag":    cfg.get('LABEL', ''),
            "branch": cfg.get('PROJECT', ''),
            "error":  ""
        })
    except Exception as e:
        return jsonify({"success": False, "tag": "", "branch": "", "error": str(e)})

@app.route('/srn/tags')
def srn_get_tags():
    try:
        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        result    = git_manager.get_tags(repo_path)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "tags": [], "error": str(e)})

@app.route('/srn/update-config', methods=['POST'])
def srn_update_config():
    try:
        data   = request.get_json()
        tag    = data.get('tag', '').strip()
        branch = data.get('branch', '').strip()
        if not tag or not branch:
            return jsonify({"success": False, "error": "Tag and branch are required."})
        _write_srn_config(_SRN_CONFIG_PATH, {'LABEL': tag, 'PROJECT': branch})
        return jsonify({"success": True, "error": ""})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/srn/status')
def srn_status():
    try:
        config = config_loader.load_config()
        srn_base, srn_pandoc, _ = _get_srn_paths(config)
        script_ok = os.path.isfile(os.path.join(srn_base, 'srn_create.sh'))
        pandoc_ok = os.path.isdir(srn_pandoc) and bool(os.listdir(srn_pandoc))
        deployed  = script_ok and pandoc_ok
        return jsonify({"success": True, "deployed": deployed, "error": ""})
    except Exception as e:
        return jsonify({"success": False, "deployed": False, "error": str(e)})

@app.route('/srn/deploy', methods=['POST'])
def srn_deploy():
    try:
        config = config_loader.load_config()
        srn_base, srn_pandoc, srn_build = _get_srn_paths(config)

        # Step 1: copy source files to srn_base (skip pandoc dir - handled below)
        os.makedirs(srn_base,  exist_ok=True)
        os.makedirs(srn_build, exist_ok=True)
        for item in os.listdir(_SRN_SOURCE_DIR):
            src  = os.path.join(_SRN_SOURCE_DIR, item)
            dest = os.path.join(srn_base, item)
            if os.path.isfile(src):
                shutil.copy2(src, dest)
            elif os.path.isdir(src) and item != 'pandoc':
                if os.path.exists(dest):
                    shutil.rmtree(dest)
                shutil.copytree(src, dest)

        # Step 2: extract pandoc tarball into srn_pandoc_dir
        tarball = os.path.join(_SRN_SOURCE_DIR, 'pandoc', 'pandoc-3.9-linux-amd64.tar.gz')
        if not os.path.isfile(tarball):
            return jsonify({"success": False, "error": f"Pandoc tarball not found: {tarball}"})
        os.makedirs(srn_pandoc, exist_ok=True)
        with tarfile.open(tarball, 'r:gz') as tar:
            _safe_tar_extract(tar, srn_pandoc)

        return jsonify({"success": True, "path": srn_base, "error": ""})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/srn/generate', methods=['POST'])
def srn_generate():
    """Start SRN generation as a background process with log tracking."""
    try:
        req_data = request.get_json(silent=True) or {}
        config = config_loader.load_config()
        srn_base, _, srn_build = _get_srn_paths(config)
        script_path = os.path.join(srn_base, 'srn_create.sh')

        if not os.path.isfile(script_path):
            return jsonify({"success": False, "error": "SRN not deployed. Run Deploy SRN first."})

        projects_path   = config.get('scanner', 'projects_path').rstrip('/')
        idaspkg_relpath = config.get('scanner', 'idaspkg_path', fallback='/repos/pxeBase/iDASpkg').rstrip('/')
        repo_path       = git_manager.get_repo_path(config)

        os.makedirs(srn_build, exist_ok=True)

        env = os.environ.copy()
        env['SRN_BUILD_DIR']   = srn_build
        env['PROJECTS_PATH']   = projects_path
        env['IDASPKG_RELPATH'] = idaspkg_relpath
        env['REPO_DIR']        = repo_path

        # Read tag/branch from SRN config for tracking info
        cfg = _parse_srn_config(_SRN_CONFIG_PATH)
        tag    = cfg.get('LABEL', 'unknown')
        branch = cfg.get('PROJECT', 'unknown')

        # Generate unique run ID
        now      = datetime.datetime.now()
        date_str = now.strftime('%Y%m%d_%H%M%S')
        safe_tag = re.sub(r'[^a-zA-Z0-9_.-]', '_', tag)
        run_id   = f"srn_{safe_tag}_{date_str}"

        # Get PID paths
        srn_pid_dir, srn_pid_logs = _get_srn_pid_paths()

        # Start background process
        log_path = os.path.join(srn_pid_logs, f'{run_id}.log')
        log_file = open(log_path, 'w')

        proc = subprocess.Popen(
            ['bash', script_path],
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=env,
            cwd=srn_base,
            start_new_session=True
        )

        # Create tracking JSON
        owner = req_data.get('owner', '')
        tracking = {
            "id":         run_id,
            "tag":        tag,
            "branch":     branch,
            "pid":        proc.pid,
            "log_path":   log_path,
            "started_at": now.strftime('%Y-%m-%d %H:%M:%S'),
            "status":     "running",
            "owner":      owner
        }

        json_path = os.path.join(srn_pid_dir, f'{run_id}.json')
        with open(json_path, 'w') as f:
            json.dump(tracking, f, indent=2)

        return jsonify({"success": True, "run_id": run_id, "pid": proc.pid})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# ---- SRN Background Run Management ------------------------------------------

@app.route('/srn/runs/list')
def srn_runs_list():
    """List all SRN runs, checking PID status."""
    try:
        srn_pid_dir, _ = _get_srn_pid_paths()
        runs = []

        for fname in sorted(os.listdir(srn_pid_dir), reverse=True):
            if not fname.endswith('.json'):
                continue
            json_path = os.path.join(srn_pid_dir, fname)
            try:
                with open(json_path, 'r') as f:
                    run = json.load(f)

                # Check if process is still running
                pid = run.get('pid')
                if pid and run.get('status') == 'running':
                    try:
                        os.kill(pid, 0)
                    except OSError:
                        run['status'] = 'finished'
                        with open(json_path, 'w') as fw:
                            json.dump(run, fw, indent=2)

                runs.append(run)
            except (json.JSONDecodeError, IOError):
                continue

        return jsonify({"success": True, "runs": runs})

    except Exception as e:
        return jsonify({"success": False, "runs": [], "error": str(e)})

@app.route('/srn/runs/stop', methods=['POST'])
def srn_runs_stop():
    """Stop a running SRN process by run_id."""
    try:
        data   = request.get_json()
        run_id = data.get('run_id', '')

        if not run_id:
            return jsonify({"success": False, "error": "run_id is required."})

        if not re.match(r'^srn_[\w.\-]+$', run_id):
            return jsonify({"success": False, "error": "Invalid run ID."})

        srn_pid_dir, _ = _get_srn_pid_paths()
        json_path = os.path.join(srn_pid_dir, f'{run_id}.json')

        if not os.path.exists(json_path):
            return jsonify({"success": False, "error": "Run not found."})

        with open(json_path, 'r') as f:
            run = json.load(f)

        pid = run.get('pid')
        if not pid:
            return jsonify({"success": False, "error": "No PID found."})

        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            run['status'] = 'stopped'
            with open(json_path, 'w') as fw:
                json.dump(run, fw, indent=2)
            return jsonify({"success": True, "message": f"SRN run {run_id} stopped."})
        except OSError:
            run['status'] = 'finished'
            with open(json_path, 'w') as fw:
                json.dump(run, fw, indent=2)
            return jsonify({"success": False, "error": "Process is not running."})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/srn/runs/log/<run_id>')
def srn_runs_log(run_id):
    """Get the log content for an SRN run."""
    try:
        if not re.match(r'^srn_[\w.\-]+$', run_id):
            return jsonify({"success": False, "error": "Invalid run ID."})

        srn_pid_dir, _ = _get_srn_pid_paths()
        json_path = os.path.join(srn_pid_dir, f'{run_id}.json')

        if not os.path.exists(json_path):
            return jsonify({"success": False, "error": "Run not found."})

        with open(json_path, 'r') as f:
            run = json.load(f)

        log_path = run.get('log_path', '')
        if not log_path or not os.path.exists(log_path):
            return jsonify({"success": True, "log": "Log file not found yet.", "status": run.get('status', 'unknown')})

        tail = request.args.get('tail', type=int, default=0)

        with open(log_path, 'r', errors='replace') as f:
            if tail > 0:
                lines = f.readlines()
                content = ''.join(lines[-tail:])
            else:
                content = f.read()

        # Check PID status
        pid    = run.get('pid')
        status = run.get('status', 'unknown')
        if pid and status == 'running':
            try:
                os.kill(pid, 0)
            except OSError:
                status = 'finished'
                run['status'] = status
                with open(json_path, 'w') as fw:
                    json.dump(run, fw, indent=2)

        return jsonify({"success": True, "log": content, "status": status})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/srn/runs/delete', methods=['POST'])
def srn_runs_delete():
    """Delete an SRN run tracking file and its log."""
    try:
        data   = request.get_json()
        run_id = data.get('run_id', '')

        if not run_id:
            return jsonify({"success": False, "error": "run_id is required."})

        if not re.match(r'^srn_[\w.\-]+$', run_id):
            return jsonify({"success": False, "error": "Invalid run ID."})

        srn_pid_dir, _ = _get_srn_pid_paths()
        json_path = os.path.join(srn_pid_dir, f'{run_id}.json')

        if not os.path.exists(json_path):
            return jsonify({"success": False, "error": "Run not found."})

        with open(json_path, 'r') as f:
            run = json.load(f)

        # Don't delete running processes
        pid = run.get('pid')
        if pid:
            try:
                os.kill(pid, 0)
                return jsonify({"success": False, "error": "Cannot delete a running process. Stop it first."})
            except OSError:
                pass

        # Delete log file
        log_path = run.get('log_path', '')
        if log_path and os.path.exists(log_path):
            os.remove(log_path)

        # Delete JSON
        os.remove(json_path)

        return jsonify({"success": True, "message": f"SRN run {run_id} deleted."})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/srn/list')
def srn_list():
    try:
        config = config_loader.load_config()
        _, _, srn_build = _get_srn_paths(config)
        items = []
        if os.path.isdir(srn_build):
            for label_dir in sorted(os.listdir(srn_build), reverse=True):
                full = os.path.join(srn_build, label_dir)
                if not os.path.isdir(full):
                    continue
                # Read metadata file if present
                project = branch = ''
                date_str = datetime.datetime.fromtimestamp(os.path.getmtime(full)).strftime('%Y-%m-%d %H:%M')
                meta_file = os.path.join(full, '.srn_meta')
                if os.path.isfile(meta_file):
                    with open(meta_file) as mf:
                        for mline in mf:
                            k, _, v = mline.strip().partition('=')
                            if k == 'project':
                                branch = v   # project field holds the branch name
                            elif k == 'label':
                                pass         # label_dir is already the label
                            elif k == 'generated':
                                date_str = v  # use written timestamp if present
                mtime = os.path.getmtime(full)
                files = [f for f in os.listdir(full) if not f.startswith('.')]
                items.append({
                    "label":   label_dir,
                    "branch":  branch,
                    "date":    date_str,
                    "files":   files
                })
        return jsonify({"success": True, "items": items, "error": ""})
    except Exception as e:
        return jsonify({"success": False, "items": [], "error": str(e)})

@app.route('/srn/tags-for-branch')
def srn_tags_for_branch():
    try:
        branch    = request.args.get('branch', '').strip()
        config    = config_loader.load_config()
        repo_path = git_manager.get_repo_path(config)
        if not branch:
            return jsonify({"success": False, "tags": [], "error": "branch parameter required"})

        # Try the branch name as-is first, then with origin/ prefix for remote-only branches
        for ref in [branch, f'origin/{branch}']:
            result = subprocess.run(
                ['git', '-C', repo_path, 'tag', '--merged', ref, '--sort=-version:refname'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            if result.returncode == 0:
                tags = [t.strip() for t in result.stdout.decode().splitlines() if t.strip()]
                return jsonify({"success": True, "tags": tags, "error": ""})

        return jsonify({"success": False, "tags": [], "error": result.stderr.decode()})
    except Exception as e:
        return jsonify({"success": False, "tags": [], "error": str(e)})

@app.route('/srn/delete/<label>', methods=['DELETE'])
def srn_delete(label):
    try:
        # Sanitise label — only allow alphanumeric, dots, dashes, underscores
        if not re.match(r'^[\w.\-]+$', label):
            return jsonify({"success": False, "error": "Invalid label name"})
        config = config_loader.load_config()
        _, _, srn_build = _get_srn_paths(config)
        target = os.path.realpath(os.path.join(srn_build, label))
        # Path-traversal guard
        if not target.startswith(os.path.realpath(srn_build) + os.sep):
            return jsonify({"success": False, "error": "Invalid path"})
        if not os.path.isdir(target):
            return jsonify({"success": False, "error": "SRN not found"})
        shutil.rmtree(target)
        return jsonify({"success": True, "error": ""})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/srn/download/<label>')
def srn_download(label):
    try:
        if not re.match(r'^[\w.\-]+$', label):
            return jsonify({"success": False, "error": "Invalid label name"}), 400
        config = config_loader.load_config()
        _, _, srn_build = _get_srn_paths(config)
        target = os.path.realpath(os.path.join(srn_build, label))
        if not target.startswith(os.path.realpath(srn_build) + os.sep):
            return jsonify({"success": False, "error": "Invalid path"}), 400
        if not os.path.isdir(target):
            return jsonify({"success": False, "error": "SRN not found"}), 404
        import io
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            tar.add(target, arcname=label)
        buf.seek(0)
        from flask import send_file
        return send_file(
            buf,
            mimetype='application/gzip',
            as_attachment=True,
            download_name=f'{label}.tar.gz'
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# End SRN endpoints
# ============================================================

# ============================================================
# Admin endpoints
# ============================================================

@app.route('/admin/check')
def admin_check():
    """Check if the current user is an admin."""
    username = request.args.get('username', '').strip()
    if not username:
        return jsonify({"is_admin": False})
    return jsonify({"is_admin": user_manager.is_admin(username)})


@app.route('/admin/activity-log')
def admin_activity_log():
    """Returns the activity log. Admin only."""
    username = request.args.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    user_filter = request.args.get('filter_user', '').strip() or None
    limit = int(request.args.get('limit', 500))
    if _storage_is_db():
        entries = _db_get_activity_log(limit=limit, username_filter=user_filter)
    else:
        entries = user_manager.get_activity_log(limit=limit, username_filter=user_filter)
    return jsonify({"success": True, "entries": entries})


@app.route('/admin/projects', methods=['GET'])
def admin_get_projects():
    """Returns all project assignments."""
    if _storage_is_db():
        assignments = _db_get_all_assignments()
    else:
        assignments = user_manager.get_all_projects()
    status_labels = user_manager.get_status_labels()
    status_colors = user_manager.get_status_colors()
    return jsonify({
        "success": True,
        "assignments": assignments,
        "status_labels": status_labels,
        "status_colors": status_colors
    })


@app.route('/admin/projects/move', methods=['POST'])
def admin_move_project():
    """Move a project from one user to another. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    project_name = data.get('project_name', '').strip()
    from_user = data.get('from_user', '').strip()
    to_user = data.get('to_user', '').strip()

    if not all([project_name, from_user, to_user]):
        return jsonify({"success": False, "error": "Missing required fields."})

    if _storage_is_db():
        ok, msg = _db_move_project_assignment(project_name, from_user, to_user)
    else:
        ok, msg = user_manager.move_project(project_name, from_user, to_user)
    if ok:
        _log_activity(admin_user, 'move_project',
            f'Moved {project_name} from {from_user} to {to_user}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/projects/status', methods=['POST'])
def admin_set_project_status():
    """Set the status/color of a project. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    username = data.get('username', '').strip()
    project_name = data.get('project_name', '').strip()
    status = data.get('status', '').strip()

    if _storage_is_db():
        ok, msg = _db_set_project_status(username, project_name, status)
    else:
        ok, msg = user_manager.set_project_status(username, project_name, status)
    if ok:
        _log_activity(admin_user, 'set_project_status',
            f'Set {project_name} ({username}) to {status}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/projects/add', methods=['POST'])
def admin_add_project():
    """Add a new project to a user. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    username = data.get('username', '').strip()
    project_name = data.get('project_name', '').strip()
    status = data.get('status', 'wip').strip()

    if not username or not project_name:
        return jsonify({"success": False, "error": "Username and project name are required."})

    if _storage_is_db():
        ok, msg = _db_add_project_assignment(username, project_name, status)
    else:
        ok, msg = user_manager.add_project(username, project_name, status)
    if ok:
        _log_activity(admin_user, 'add_project',
            f'Added {project_name} to {username}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/projects/remove', methods=['POST'])
def admin_remove_project():
    """Remove a project from a user. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    username = data.get('username', '').strip()
    project_name = data.get('project_name', '').strip()

    if _storage_is_db():
        ok, msg = _db_remove_project_assignment(username, project_name)
    else:
        ok, msg = user_manager.remove_project(username, project_name)
    if ok:
        _log_activity(admin_user, 'remove_project',
            f'Removed {project_name} from {username}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/projects/available', methods=['GET'])
def admin_available_projects():
    """Returns the list of master projects not yet assigned to any user."""
    if _storage_is_db():
        available = _db_get_available_projects()
    else:
        available = user_manager.get_available_projects()
    return jsonify({"success": True, "projects": available})


@app.route('/admin/projects/master', methods=['GET'])
def admin_master_projects():
    """Returns all master projects with their assignment info."""
    if _storage_is_db():
        master = _db_get_master_projects()
        result = []
        for p in master:
            assigned_to, status = _db_get_project_assignment(p['name'])
            result.append({
                "name": p['name'], "folder": p['folder'],
                "assigned_to": assigned_to or '', "status": status or ''
            })
    else:
        master = user_manager.get_master_projects()
        result = []
        for p in master:
            assigned_to, status = user_manager.get_project_assignment(p['name'])
            result.append({
                "name": p['name'], "folder": p['folder'],
                "assigned_to": assigned_to or '', "status": status or ''
            })
    return jsonify({"success": True, "projects": result})


@app.route('/admin/projects/master/add', methods=['POST'])
def admin_add_master_project():
    """Add a new project to the master list. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    name = data.get('name', '').strip()
    folder = data.get('folder', '').strip()
    assign_to = data.get('assign_to', '').strip()
    status = data.get('status', 'wip').strip()

    if not name:
        return jsonify({"success": False, "error": "Project name is required."})
    if not folder:
        folder = name.lower().replace(' ', '-')

    if _storage_is_db():
        ok, msg = _db_add_master_project(name, folder)
        if ok:
            _db_log_activity(admin_user, 'create_project', f'Created project {name} (folder: {folder})')
            if assign_to:
                _db_add_project_assignment(assign_to, name, status)
                _db_log_activity(admin_user, 'assign_project', f'Assigned {name} to {assign_to}')
    else:
        ok, msg = user_manager.add_master_project(name, folder)
        if ok:
            user_manager.log_activity(admin_user, 'create_project', f'Created project {name} (folder: {folder})')
            # Optionally assign to a user
            if assign_to:
                user_manager.add_project(assign_to, name, status)
                user_manager.log_activity(admin_user, 'assign_project', f'Assigned {name} to {assign_to}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/projects/master/update', methods=['POST'])
def admin_update_master_project():
    """Update a project in the master list. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    old_name = data.get('old_name', '').strip()
    new_name = data.get('name', '').strip()
    new_folder = data.get('folder', '').strip()

    if not old_name or not new_name:
        return jsonify({"success": False, "error": "Project name is required."})
    if not new_folder:
        new_folder = new_name.lower().replace(' ', '-')

    if _storage_is_db():
        ok, msg = _db_update_master_project(old_name, new_name, new_folder)
    else:
        ok, msg = user_manager.update_master_project(old_name, new_name, new_folder)
    if ok:
        _log_activity(admin_user, 'update_project', f'Updated project {old_name} \u2192 {new_name} (folder: {new_folder})')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/projects/master/delete', methods=['POST'])
def admin_delete_master_project():
    """Delete a project from the master list and all assignments. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    name = data.get('name', '').strip()
    if not name:
        return jsonify({"success": False, "error": "Project name is required."})

    if _storage_is_db():
        ok, msg = _db_delete_master_project(name)
    else:
        ok, msg = user_manager.delete_master_project(name)
    if ok:
        _log_activity(admin_user, 'delete_project', f'Deleted project {name}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/users', methods=['GET'])
def admin_list_managed_users():
    """List only managed users (those in projects.json)."""
    if _storage_is_db():
        return jsonify({"success": True, "users": _db_list_users()})
    assignments = user_manager.get_all_projects()
    result = []
    for username, info in assignments.items():
        result.append({
            "username": username,
            "display_name": info.get('display_name', '') or user_manager.get_display_name(username),
            "is_admin": user_manager.is_admin(username),
            "projects": info.get('projects', []),
        })
    return jsonify({"success": True, "users": result})


@app.route('/admin/users/available', methods=['GET'])
def admin_available_users():
    """List system users NOT in the managed list (available to add)."""
    assignments = user_manager.get_all_projects()
    system_users = user_manager.get_system_users()
    available = [u for u in system_users if u not in assignments]
    return jsonify({"success": True, "users": available})


@app.route('/admin/users/toggle-admin', methods=['POST'])
def admin_toggle_admin():
    """Toggle admin status for a user. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    target_user = data.get('username', '').strip()
    make_admin = data.get('is_admin', False)

    user_manager.set_admin(target_user, make_admin)  # always keep admin.json in sync
    if _storage_is_db():
        _db_toggle_admin(target_user, make_admin)
    action = 'grant_admin' if make_admin else 'revoke_admin'
    _log_activity(admin_user, action, f'{action} for {target_user}')
    return jsonify({"success": True})


@app.route('/admin/users/add-to-list', methods=['POST'])
def admin_add_user_to_list():
    """Add a system user to the managed users list. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    target_user = data.get('username', '').strip()
    user_manager.add_user_to_projects(target_user)  # always keep JSON in sync
    if _storage_is_db():
        _db_add_user(target_user)
    _log_activity(admin_user, 'add_user_to_list', f'Added {target_user} to managed users')
    return jsonify({"success": True})


@app.route('/admin/users/remove-from-list', methods=['POST'])
def admin_remove_user_from_list():
    """Remove a user from the managed users list. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    target_user = data.get('username', '').strip()
    user_manager.remove_user_from_projects(target_user)  # always keep JSON in sync
    if _storage_is_db():
        _db_remove_user(target_user)
    _log_activity(admin_user, 'remove_user_from_list', f'Removed {target_user} from managed users')
    return jsonify({"success": True})


@app.route('/admin/users/update', methods=['POST'])
def admin_update_user():
    """Update display name for a user. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    target_user = data.get('username', '').strip()
    display_name = data.get('display_name', '').strip()
    if not target_user:
        return jsonify({"success": False, "error": "Username is required."})
    user_manager.update_display_name(target_user, display_name)  # always keep JSON in sync
    if _storage_is_db():
        _db_update_display_name(target_user, display_name)
    _log_activity(admin_user, 'update_user', f'Updated display name for {target_user} to "{display_name}"')
    return jsonify({"success": True})


@app.route('/admin/users/add-db-user', methods=['POST'])
def admin_add_db_user():
    """Create a new DB-only user (no OS account required). Only in DB storage mode."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    if not _storage_is_db():
        return jsonify({"success": False, "error": "DB storage mode is required."})

    username = data.get('username', '').strip().lower()
    if not username:
        return jsonify({"success": False, "error": "Username is required."})
    if not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
        return jsonify({"success": False, "error": "Invalid username. Use only letters, numbers, _ . -"})

    # Check for duplicates
    assignments = _db_get_all_assignments()
    if username in assignments:
        return jsonify({"success": False, "error": f"User '{username}' already exists."})

    user_manager.add_user_to_projects(username)   # keep JSON in sync
    _db_add_user(username)
    _log_activity(admin_user, 'add_db_user', f'Created DB user {username}')
    return jsonify({"success": True})


@app.route('/admin/users/bulk-action', methods=['POST'])
def admin_bulk_action():
    """Perform a bulk action (delete or set_role) on multiple users. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    action    = data.get('action', '')       # 'delete' | 'set_admin' | 'set_user'
    usernames = data.get('usernames', [])    # list of strings

    if action not in ('delete', 'set_admin', 'set_user'):
        return jsonify({"success": False, "error": "Invalid action."})
    if not usernames or not isinstance(usernames, list):
        return jsonify({"success": False, "error": "No users provided."})

    errors = []
    for username in usernames:
        username = str(username).strip()
        if not username or not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            continue
        if username == admin_user:
            continue  # never self-modify
        try:
            if action == 'delete':
                user_manager.remove_user_from_projects(username)
                if _storage_is_db():
                    _db_remove_user(username)
                _log_activity(admin_user, 'bulk_delete_user', f'Bulk-deleted {username}')
            elif action in ('set_admin', 'set_user'):
                make_admin = (action == 'set_admin')
                user_manager.set_admin(username, make_admin)
                if _storage_is_db():
                    _db_toggle_admin(username, make_admin)
                _log_activity(admin_user, 'bulk_set_role', f'Bulk set {username} as {"admin" if make_admin else "user"}')
        except Exception as e:
            errors.append(f'{username}: {str(e)}')

    if errors:
        return jsonify({"success": True, "warnings": errors})
    return jsonify({"success": True})

# End Admin endpoints
# ============================================================

# ============================================================
# Report endpoints
# ============================================================

@app.route('/report/project-info', methods=['GET'])
def report_project_info():
    """Returns project info data for the project information page."""
    try:
        if _storage_is_db():
            raw = _db_get_user_projects()
            projects = []
            for p in raw:
                projects.append({
                    'name': p['name'], 'folder': p['folder'],
                    'assigned_to': p['assigned_to'], 'display_name': p['display_name'],
                    'status': p['status'],
                    'status_label': user_manager.get_status_labels().get(p['status'], 'Unassigned'),
                    'notes': p['notes'],
                })
        else:
            master_projects = user_manager.get_master_projects()
            projects = []
            for mp in master_projects:
                assigned_to, status = user_manager.get_project_assignment(mp['name'])
                display_name = ''
                if assigned_to:
                    display_name = user_manager.get_display_name(assigned_to)
                projects.append({
                    'name': mp['name'], 'folder': mp['folder'],
                    'assigned_to': assigned_to or '', 'display_name': display_name,
                    'status': status or '',
                    'status_label': user_manager.get_status_labels().get(status, 'Unassigned'),
                    'notes': mp.get('notes', ''),
                })

        # Status counts
        counts = {}
        for p in projects:
            label = p['status_label']
            counts[label] = counts.get(label, 0) + 1

        return jsonify({"success": True, "projects": projects, "counts": counts})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/report/save-notes', methods=['POST'])
def report_save_notes():
    """Save notes and optionally statuses for multiple projects at once."""
    try:
        data = request.get_json()
        notes_map = data.get('notes', {})   # { "PROJECT_NAME": "notes text", ... }
        status_map = data.get('statuses', {})  # { "PROJECT_NAME": "wip", ... }
        for project_name, notes_text in notes_map.items():
            if _storage_is_db():
                _db_set_project_notes(project_name, notes_text)
            else:
                user_manager.set_project_notes(project_name, notes_text)
        valid_statuses = {'done', 'not_ok', 'idle', 'wip'}
        if _storage_is_db():
            all_st = _db_get_all_statuses()
            valid_statuses = set(_db_status_name_to_key(s['name']) for s in all_st)
        for project_name, status in status_map.items():
            if status not in valid_statuses:
                continue
            if _storage_is_db():
                username, _ = _db_get_project_assignment(project_name)
                if username:
                    _db_set_project_status(username, project_name, status)
            else:
                username, _ = user_manager.get_project_assignment(project_name)
                if username:
                    user_manager.set_project_status(username, project_name, status)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/report/download', methods=['GET'])
def report_download():
    """Generates and downloads the project report as DOCX."""
    try:
        doc_bytes, filename = report_generator.generate_project_report()
        return Response(
            doc_bytes,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# End Report endpoints
# ============================================================

# ============================================================
# Processes endpoints
# ============================================================

@app.route('/system/processes')
def system_processes():
    """Returns the current list of running processes, sorted by CPU%."""
    try:
        settings = _get_system_settings()

        if settings['mode'] == 'remote' and settings.get('remote_ip'):
            raw = _run_remote(['ps', 'aux', '--sort=-%cpu'], settings['remote_ip'], settings.get('ssh_user', 'root'))
            lines = raw.splitlines()
        else:
            result = subprocess.run(
                ['ps', 'aux', '--sort=-%cpu'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            lines = result.stdout.decode('utf-8', errors='replace').splitlines()

        processes = []
        for line in lines[1:]:  # skip header
            parts = line.split(None, 10)
            if len(parts) < 11:
                continue
            try:
                processes.append({
                    'user':    parts[0],
                    'pid':     int(parts[1]),
                    'cpu':     float(parts[2]),
                    'mem':     float(parts[3]),
                    'vsz':     int(parts[4]),
                    'rss':     int(parts[5]),
                    'stat':    parts[7],
                    'command': parts[10][:120],
                })
            except (ValueError, IndexError):
                continue
        return jsonify({"success": True, "processes": processes})
    except Exception as e:
        return jsonify({"success": False, "processes": [], "error": str(e)})


@app.route('/system/kill-process', methods=['POST'])
def system_kill_process():
    """Kill a process by PID. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    pid = data.get('pid')
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return jsonify({"success": False, "error": "Invalid PID."})

    # Safety: refuse to kill PID 1 or own process
    if pid <= 1:
        return jsonify({"success": False, "error": "Cannot kill this process."})

    settings = _get_system_settings()

    if settings['mode'] == 'remote' and settings.get('remote_ip'):
        try:
            _run_remote(['kill', '-15', str(pid)], settings['remote_ip'], settings.get('ssh_user', 'root'))
            user_manager.log_activity(admin_user, 'kill_process', 'Killed PID {} on {}'.format(pid, settings['remote_ip']))
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)})

    try:
        os.kill(pid, 15)  # SIGTERM
        user_manager.log_activity(admin_user, 'kill_process', f'Killed PID {pid}')
        return jsonify({"success": True})
    except ProcessLookupError:
        return jsonify({"success": False, "error": "Process not found (may have already exited)."})
    except PermissionError:
        return jsonify({"success": False, "error": "Permission denied. Cannot kill this process."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/system/process/<int:pid>')
def system_process_detail(pid):
    """Returns detailed info for a single process by reading /proc/<pid>."""
    if pid <= 0:
        return jsonify({"success": False, "error": "Invalid PID."})

    settings = _get_system_settings()
    is_remote = settings['mode'] == 'remote' and settings.get('remote_ip')

    detail = {"pid": pid}

    if is_remote:
        remote_ip = settings['remote_ip']
        ssh_user = settings.get('ssh_user', 'root')
        try:
            out = _run_remote(['cat', '/proc/{}/status'.format(pid)], remote_ip, ssh_user)
            for line in out.splitlines():
                parts = line.strip().split(':', 1)
                if len(parts) == 2:
                    detail[parts[0].strip()] = parts[1].strip()
        except Exception:
            return jsonify({"success": False, "error": "Process not found on remote host."})
        try:
            out = _run_remote(['cat', '/proc/{}/cmdline'.format(pid)], remote_ip, ssh_user)
            detail['cmdline_full'] = out.replace('\x00', ' ').strip()
        except Exception:
            detail['cmdline_full'] = ''
        try:
            out = _run_remote(['cat', '/proc/{}/io'.format(pid)], remote_ip, ssh_user)
            io = {}
            for line in out.splitlines():
                parts = line.strip().split(':', 1)
                if len(parts) == 2:
                    io[parts[0].strip()] = parts[1].strip()
            detail['io'] = io
        except Exception:
            detail['io'] = {}
        try:
            out = _run_remote(['cat', '/proc/{}/wchan'.format(pid)], remote_ip, ssh_user)
            detail['wchan'] = out.strip()
        except Exception:
            detail['wchan'] = ''
        detail['env_var_count'] = None
        return jsonify({"success": True, "detail": detail})

    # Local mode
    # /proc/<pid>/status
    try:
        with open('/proc/{}/status'.format(pid), 'r') as f:
            for line in f:
                parts = line.strip().split(':', 1)
                if len(parts) == 2:
                    detail[parts[0].strip()] = parts[1].strip()
    except IOError:
        return jsonify({"success": False, "error": "Process not found."})

    # /proc/<pid>/cmdline (full command with args)
    try:
        with open('/proc/{}/cmdline'.format(pid), 'rb') as f:
            raw = f.read().replace(b'\x00', b' ').decode('utf-8', errors='replace').strip()
            detail['cmdline_full'] = raw
    except IOError:
        detail['cmdline_full'] = ''

    # /proc/<pid>/io (I/O stats)
    try:
        with open('/proc/{}/io'.format(pid), 'r') as f:
            io = {}
            for line in f:
                parts = line.strip().split(':', 1)
                if len(parts) == 2:
                    io[parts[0].strip()] = parts[1].strip()
            detail['io'] = io
    except IOError:
        detail['io'] = {}

    # /proc/<pid>/wchan (what the process is waiting on)
    try:
        with open('/proc/{}/wchan'.format(pid), 'r') as f:
            detail['wchan'] = f.read().strip()
    except IOError:
        detail['wchan'] = ''

    # /proc/<pid>/environ - count only (don't leak env vars)
    try:
        with open('/proc/{}/environ'.format(pid), 'rb') as f:
            count = len(f.read().split(b'\x00'))
        detail['env_var_count'] = count
    except IOError:
        detail['env_var_count'] = None

    return jsonify({"success": True, "detail": detail})

# End Processes endpoints
# ============================================================

# ============================================================
# System Settings endpoints (Local / Remote mode)
# ============================================================

def _get_system_settings():
    """Load system settings from /opt/pulpitans/system_settings.json."""
    base_dir = user_manager._get_base_dir()
    path = os.path.join(base_dir, 'system_settings.json')
    defaults = {
        'mode': 'local', 'remote_ip': '', 'ssh_user': 'root',
        'db': {'type': 'mariadb', 'host': '127.0.0.1', 'port': 3306, 'name': '', 'user': '', 'password': ''},
        'auth': {'method': 'system', 'sso': {}},
        'storage_mode': 'local'
    }
    if os.path.isfile(path):
        with open(path, 'r') as f:
            data = json.load(f)
        for k, v in defaults.items():
            data.setdefault(k, v)
        if 'db' in data and isinstance(data['db'], dict):
            for dk, dv in defaults['db'].items():
                data['db'].setdefault(dk, dv)
        return data
    return dict(defaults)


def _save_system_settings(data):
    base_dir = user_manager._get_base_dir()
    path = os.path.join(base_dir, 'system_settings.json')
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)


# ============================================================
# Database Data Layer (used when storage_mode == 'database')
# ============================================================

def _storage_is_db():
    """Returns True if storage mode is set to 'database'."""
    return _get_system_settings().get('storage_mode', 'local') == 'database'


def _db_connect():
    """Get a PyMySQL connection from system settings. Returns None if unavailable."""
    try:
        import pymysql
        s = _get_system_settings()
        db = s.get('db', {})
        if not db.get('host') or not db.get('user') or not db.get('name'):
            return None
        return pymysql.connect(
            host=db['host'], port=int(db.get('port', 3306)),
            user=db['user'], password=db.get('password', ''),
            database=db['name'], connect_timeout=5, autocommit=True,
            cursorclass=pymysql.cursors.DictCursor
        )
    except Exception:
        return None


# -- DB: Project Status --

def _db_get_all_statuses():
    """Returns list of all project statuses ordered by sort_order."""
    conn = _db_connect()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, color, icon, is_default, sort_order FROM project_status ORDER BY sort_order, id")
        return [{'id': r['id'], 'name': r['name'], 'color': r['color'] or 'secondary',
                 'icon': r['icon'] or 'circle', 'is_default': bool(r['is_default']),
                 'sort_order': r['sort_order']} for r in cur.fetchall()]
    except Exception:
        return []
    finally:
        conn.close()


def _db_get_status_name(status_id):
    """Resolve a status_id to its name. Returns '' if not found."""
    conn = _db_connect()
    if not conn: return ''
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM project_status WHERE id=%s", (status_id,))
        row = cur.fetchone()
        return row['name'] if row else ''
    finally:
        conn.close()


def _db_status_name_to_key(status_name):
    """Convert a DB status name (e.g. 'WIP') to the legacy key (e.g. 'wip') for JSON compat."""
    _map = {'DONE': 'done', 'NOT OK': 'not_ok', 'IDLE': 'idle', 'WIP': 'wip'}
    return _map.get(status_name, status_name.lower().replace(' ', '_'))


def _db_resolve_status_id(status_key):
    """Convert legacy status key (e.g. 'wip') to a status_id in project_status table."""
    _key_to_name = {'done': 'DONE', 'not_ok': 'NOT OK', 'idle': 'IDLE', 'wip': 'WIP'}
    name = _key_to_name.get(status_key, status_key.upper() if status_key else None)
    if not name:
        return None
    conn = _db_connect()
    if not conn: return None
    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM project_status WHERE name=%s", (name,))
        row = cur.fetchone()
        return row['id'] if row else None
    finally:
        conn.close()


# -- DB: Admin Projects (admin-projects.html) --
# admin_projects has assigned_to (FK→users.id) and status_id (FK→project_status.id)

def _db_get_master_projects():
    """Read master project catalog with assigned user and status."""
    conn = _db_connect()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT ap.id, ap.name, ap.folder, u.username AS assigned_to, "
            "ps.name AS status_name "
            "FROM admin_projects ap "
            "LEFT JOIN users u ON u.id = ap.assigned_to "
            "LEFT JOIN project_status ps ON ps.id = ap.status_id "
            "ORDER BY ap.name"
        )
        return [{'id': r['id'], 'name': r['name'], 'folder': r['folder'] or '',
                 'assigned_to': r['assigned_to'] or '',
                 'status': _db_status_name_to_key(r['status_name']) if r['status_name'] else '',
                 'status_name': r['status_name'] or ''} for r in cur.fetchall()]
    finally:
        conn.close()


def _db_add_master_project(name, folder):
    conn = _db_connect()
    if not conn: return False, "DB not available"
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO admin_projects (name, folder) VALUES (%s, %s)", (name, folder))
        return True, ''
    except Exception as e:
        return False, "Project already exists." if 'Duplicate' in str(e) else str(e)
    finally:
        conn.close()


def _db_update_master_project(old_name, new_name, new_folder):
    """Rename/update a project. user_projects rows stay linked via project_id FK."""
    conn = _db_connect()
    if not conn: return False, "DB not available"
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE admin_projects SET name=%s, folder=%s WHERE name=%s",
            (new_name, new_folder, old_name)
        )
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def _db_delete_master_project(name):
    """Delete a project. ON DELETE CASCADE removes linked user_projects rows."""
    conn = _db_connect()
    if not conn: return False, "DB not available"
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM admin_projects WHERE name=%s", (name,))
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def _db_get_project_assignment(project_name):
    """Returns (username, status_key) from admin_projects."""
    conn = _db_connect()
    if not conn: return None, None
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT u.username, ps.name AS status_name "
            "FROM admin_projects ap "
            "LEFT JOIN users u ON u.id = ap.assigned_to "
            "LEFT JOIN project_status ps ON ps.id = ap.status_id "
            "WHERE ap.name = %s LIMIT 1",
            (project_name,)
        )
        row = cur.fetchone()
        if not row or not row['username']:
            return None, None
        return (row['username'], _db_status_name_to_key(row['status_name']) if row['status_name'] else '')
    finally:
        conn.close()


def _db_get_available_projects():
    """Returns names of admin_projects not assigned to any user."""
    conn = _db_connect()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM admin_projects WHERE assigned_to IS NULL ORDER BY name")
        return [r['name'] for r in cur.fetchall()]
    finally:
        conn.close()


# -- DB: User Projects (project-info.html) --
# user_projects stores the assignment (user_id FK → users, project_id FK → admin_projects)
# plus status and notes (owned by project-info page)

def _db_get_user_projects():
    """All projects with assignment info, status, and notes — for project-info page."""
    conn = _db_connect()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT ap.name, ap.folder, u.username, u.display_name, "
            "ps.name AS status_name, up.notes "
            "FROM user_projects up "
            "JOIN admin_projects ap ON ap.id = up.project_id "
            "JOIN users u ON u.id = up.user_id "
            "LEFT JOIN project_status ps ON ps.id = up.status_id "
            "ORDER BY ap.name"
        )
        results = []
        for r in cur.fetchall():
            results.append({
                'name': r['name'], 'folder': r['folder'] or '',
                'assigned_to': r['username'] or '', 'display_name': r['display_name'] or '',
                'status': _db_status_name_to_key(r['status_name']) if r['status_name'] else '',
                'notes': r['notes'] or '',
            })
        # Unassigned projects
        cur.execute(
            "SELECT ap.name, ap.folder FROM admin_projects ap "
            "WHERE ap.assigned_to IS NULL ORDER BY ap.name"
        )
        for r in cur.fetchall():
            results.append({
                'name': r['name'], 'folder': r['folder'] or '',
                'assigned_to': '', 'display_name': '', 'status': '', 'notes': '',
            })
        return results
    finally:
        conn.close()


def _db_set_project_notes(project_name, notes):
    """Save notes for a project (identified by name) in user_projects."""
    conn = _db_connect()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE user_projects up "
            "JOIN admin_projects ap ON ap.id = up.project_id "
            "SET up.notes = %s "
            "WHERE ap.name = %s",
            (notes, project_name)
        )
    finally:
        conn.close()


# -- DB: User-Project Assignments (admin-projects.html) --

def _db_get_all_assignments():
    """Returns dict {username: {display_name, projects: [{name, status}]}}."""
    conn = _db_connect()
    if not conn: return {}
    try:
        cur = conn.cursor()
        cur.execute("SELECT username, display_name FROM users ORDER BY username")
        result = {r['username']: {'display_name': r['display_name'] or '', 'projects': []} for r in cur.fetchall()}
        cur.execute(
            "SELECT u.username, ap.name AS project_name, ps.name AS status_name, u.display_name "
            "FROM user_projects up "
            "JOIN users u ON u.id = up.user_id "
            "JOIN admin_projects ap ON ap.id = up.project_id "
            "LEFT JOIN project_status ps ON ps.id = up.status_id "
            "ORDER BY u.username, ap.name"
        )
        for r in cur.fetchall():
            un = r['username']
            if un not in result:
                result[un] = {'display_name': r['display_name'] or '', 'projects': []}
            status_key = _db_status_name_to_key(r['status_name']) if r['status_name'] else 'idle'
            result[un]['projects'].append({'name': r['project_name'], 'status': status_key})
        return result
    finally:
        conn.close()


def _db_add_project_assignment(username, project_name, status='wip'):
    """Assign a user to a project. Also updates admin_projects.assigned_to + status_id."""
    conn = _db_connect()
    if not conn: return False, "DB not available"
    try:
        cur = conn.cursor()
        cur.execute("INSERT IGNORE INTO users (username) VALUES (%s)", (username,))
        status_id = _db_resolve_status_id(status)
        cur.execute(
            "INSERT INTO user_projects (user_id, project_id, status_id) "
            "SELECT u.id, ap.id, %s "
            "FROM users u JOIN admin_projects ap ON ap.name = %s "
            "WHERE u.username = %s "
            "ON DUPLICATE KEY UPDATE status_id = VALUES(status_id)",
            (status_id, project_name, username)
        )
        # Sync admin_projects
        cur.execute(
            "UPDATE admin_projects SET assigned_to = "
            "(SELECT id FROM users WHERE username = %s LIMIT 1), "
            "status_id = %s WHERE name = %s",
            (username, status_id, project_name)
        )
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def _db_remove_project_assignment(username, project_name):
    conn = _db_connect()
    if not conn: return False, "DB not available"
    try:
        cur = conn.cursor()
        cur.execute(
            "DELETE up FROM user_projects up "
            "JOIN users u ON u.id = up.user_id "
            "JOIN admin_projects ap ON ap.id = up.project_id "
            "WHERE u.username = %s AND ap.name = %s",
            (username, project_name)
        )
        # Clear admin_projects assignment
        cur.execute(
            "UPDATE admin_projects SET assigned_to = NULL, status_id = NULL WHERE name = %s",
            (project_name,)
        )
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def _db_move_project_assignment(project_name, from_user, to_user):
    """Move a project assignment from one user to another, preserving status/notes."""
    conn = _db_connect()
    if not conn: return False, "DB not available"
    try:
        cur = conn.cursor()
        cur.execute("INSERT IGNORE INTO users (username) VALUES (%s)", (to_user,))
        cur.execute(
            "UPDATE user_projects up "
            "JOIN admin_projects ap ON ap.id = up.project_id AND ap.name = %s "
            "JOIN users fu ON fu.id = up.user_id AND fu.username = %s "
            "SET up.user_id = (SELECT id FROM users WHERE username = %s LIMIT 1)",
            (project_name, from_user, to_user)
        )
        # Sync admin_projects.assigned_to
        cur.execute(
            "UPDATE admin_projects SET assigned_to = "
            "(SELECT id FROM users WHERE username = %s LIMIT 1) WHERE name = %s",
            (to_user, project_name)
        )
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


def _db_set_project_status(username, project_name, status):
    """Set status on both user_projects and admin_projects via status_id."""
    conn = _db_connect()
    if not conn: return False, "DB not available"
    try:
        cur = conn.cursor()
        status_id = _db_resolve_status_id(status)
        cur.execute(
            "UPDATE user_projects up "
            "JOIN users u ON u.id = up.user_id AND u.username = %s "
            "JOIN admin_projects ap ON ap.id = up.project_id AND ap.name = %s "
            "SET up.status_id = %s",
            (username, project_name, status_id)
        )
        # Sync admin_projects
        cur.execute("UPDATE admin_projects SET status_id = %s WHERE name = %s",
                     (status_id, project_name))
        return True, ''
    except Exception as e:
        return False, str(e)
    finally:
        conn.close()


# -- DB: Users --

def _db_list_users():
    """Returns list of user dicts for admin panel (with their project assignments)."""
    conn = _db_connect()
    if not conn: return []
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username, display_name, is_admin FROM users ORDER BY username")
        users = {r['id']: {
            'username': r['username'], 'display_name': r['display_name'] or '',
            'is_admin': bool(r['is_admin']), 'projects': []
        } for r in cur.fetchall()}
        cur.execute(
            "SELECT up.user_id, ap.name AS project_name, ps.name AS status_name "
            "FROM user_projects up "
            "JOIN admin_projects ap ON ap.id = up.project_id "
            "LEFT JOIN project_status ps ON ps.id = up.status_id "
            "ORDER BY up.user_id, ap.name"
        )
        for r in cur.fetchall():
            uid = r['user_id']
            if uid in users:
                status_key = _db_status_name_to_key(r['status_name']) if r['status_name'] else 'idle'
                users[uid]['projects'].append({'name': r['project_name'], 'status': status_key})
        return list(users.values())
    finally:
        conn.close()


def _db_add_user(username):
    conn = _db_connect()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("INSERT IGNORE INTO users (username) VALUES (%s)", (username,))
    finally:
        conn.close()


def _db_remove_user(username):
    """Delete user. ON DELETE CASCADE removes user_projects and user_config rows."""
    conn = _db_connect()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE username=%s", (username,))
    finally:
        conn.close()


def _db_toggle_admin(username, make_admin):
    conn = _db_connect()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("INSERT IGNORE INTO users (username) VALUES (%s)", (username,))
        cur.execute("UPDATE users SET is_admin=%s WHERE username=%s", (1 if make_admin else 0, username))
    finally:
        conn.close()


def _db_update_display_name(username, display_name):
    conn = _db_connect()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET display_name=%s WHERE username=%s", (display_name, username))
    finally:
        conn.close()


def _db_get_display_name(username):
    conn = _db_connect()
    if not conn: return ''
    try:
        cur = conn.cursor()
        cur.execute("SELECT display_name FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        return row['display_name'] if row else ''
    finally:
        conn.close()


def _db_is_admin(username):
    conn = _db_connect()
    if not conn: return False
    try:
        cur = conn.cursor()
        cur.execute("SELECT is_admin FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        return bool(row['is_admin']) if row else False
    finally:
        conn.close()


def _db_get_user_config(username):
    conn = _db_connect()
    if not conn: return {'username': username}
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, username, display_name, bitbucket_username, bitbucket_password "
            "FROM users WHERE username=%s", (username,)
        )
        row = cur.fetchone()
        if not row: return {'username': username}
        cfg = {
            'username': row['username'], 'display_name': row['display_name'] or '',
            'bitbucket_username': row['bitbucket_username'] or '',
            'bitbucket_password': row['bitbucket_password'] or '',
        }
        # Extended config from user_config via user_id FK
        cur.execute(
            "SELECT config_key, config_value FROM user_config WHERE user_id=%s",
            (row['id'],)
        )
        for r in cur.fetchall():
            if r['config_key'] not in cfg:
                cfg[r['config_key']] = r['config_value']
        return cfg
    finally:
        conn.close()


def _db_save_user_config(username, data):
    conn = _db_connect()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute("INSERT IGNORE INTO users (username) VALUES (%s)", (username,))
        cur.execute(
            "UPDATE users SET display_name=%s, bitbucket_username=%s, bitbucket_password=%s "
            "WHERE username=%s",
            (data.get('display_name', ''), data.get('bitbucket_username', ''),
             data.get('bitbucket_password', ''), username)
        )
        skip = {'username', 'display_name', 'bitbucket_username', 'bitbucket_password', 'is_admin'}
        for k, v in data.items():
            if k in skip: continue
            # Resolve user_id in the INSERT using a subquery
            cur.execute(
                "INSERT INTO user_config (user_id, config_key, config_value) "
                "SELECT id, %s, %s FROM users WHERE username=%s "
                "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
                (k, str(v), username)
            )
    finally:
        conn.close()


# -- DB: Activity Log --

def _db_log_activity(username, action, details=''):
    """Log an action. user_id is resolved from username (NULL if user not found)."""
    conn = _db_connect()
    if not conn: return
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO activity_log (user_id, username, action, details) "
            "VALUES ((SELECT id FROM users WHERE username=%s LIMIT 1), %s, %s, %s)",
            (username, username, action, details)
        )
    except Exception:
        pass
    finally:
        conn.close()


def _db_get_activity_log(limit=500, username_filter=None):
    conn = _db_connect()
    if not conn: return []
    try:
        cur = conn.cursor()
        if username_filter:
            cur.execute(
                "SELECT al.timestamp, al.username, al.action, al.details "
                "FROM activity_log al "
                "WHERE al.username = %s "
                "ORDER BY al.timestamp DESC LIMIT %s",
                (username_filter, limit)
            )
        else:
            cur.execute(
                "SELECT al.timestamp, al.username, al.action, al.details "
                "FROM activity_log al "
                "ORDER BY al.timestamp DESC LIMIT %s",
                (limit,)
            )
        return [
            {'timestamp': str(r['timestamp']), 'username': r['username'],
             'action': r['action'], 'details': r['details'] or ''}
            for r in cur.fetchall()
        ]
    finally:
        conn.close()


def _log_activity(username, action, details=''):
    """Log to JSON (always) and also to DB if storage mode is database."""
    user_manager.log_activity(username, action, details)
    if _storage_is_db():
        _db_log_activity(username, action, details)


# End DB Data Layer


def _run_remote(cmd_list, remote_ip, ssh_user='root'):
    """Run a command on a remote host via SSH and return stdout."""
    ssh_cmd = [
        'ssh', '-o', 'StrictHostKeyChecking=no',
        '-o', 'ConnectTimeout=5',
        '-o', 'BatchMode=yes',
        '{}@{}'.format(ssh_user, remote_ip)
    ] + cmd_list
    result = subprocess.run(ssh_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.decode('utf-8', errors='replace').strip())
    return result.stdout.decode('utf-8', errors='replace')


@app.route('/settings/system', methods=['GET'])
def settings_get():
    """Get current system settings. Admin only."""
    username = request.args.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    settings = _get_system_settings()
    # Check if SSH key exists
    key_exists = os.path.isfile(os.path.expanduser('~/.ssh/id_rsa.pub'))
    settings['ssh_key_exists'] = key_exists
    return jsonify({"success": True, "settings": settings})


@app.route('/settings/system', methods=['POST'])
def settings_save():
    """Save system settings (mode, remote_ip). Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    mode = data.get('mode', 'local').strip()
    if mode not in ('local', 'remote'):
        return jsonify({"success": False, "error": "Invalid mode."})

    remote_ip = data.get('remote_ip', '').strip()
    ssh_user = data.get('ssh_user', 'root').strip() or 'root'

    if mode == 'remote' and not remote_ip:
        return jsonify({"success": False, "error": "Remote IP is required for remote mode."})

    # Basic IP validation
    if remote_ip and not re.match(r'^[\d\.]+$|^[\w\.\-]+$', remote_ip):
        return jsonify({"success": False, "error": "Invalid IP / hostname."})

    settings = _get_system_settings()
    settings['mode'] = mode
    settings['remote_ip'] = remote_ip
    settings['ssh_user'] = ssh_user
    _save_system_settings(settings)

    user_manager.log_activity(username, 'settings_change',
                              'Mode: {}, IP: {}'.format(mode, remote_ip or 'N/A'))
    return jsonify({"success": True})


@app.route('/settings/storage', methods=['GET'])
def settings_get_storage():
    """Get storage mode. Admin only."""
    username = request.args.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    s = _get_system_settings()
    return jsonify({"success": True, "storage_mode": s.get('storage_mode', 'local')})


@app.route('/settings/storage', methods=['POST'])
def settings_save_storage():
    """Save storage mode. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    mode = data.get('storage_mode', 'local').strip()
    if mode not in ('local', 'database'):
        return jsonify({"success": False, "error": "Invalid storage mode."})
    if mode == 'database':
        # Validate DB is configured
        s = _get_system_settings()
        db = s.get('db', {})
        if not db.get('host') or not db.get('user') or not db.get('name'):
            return jsonify({"success": False, "error": "Database not configured. Configure and test DB connection first."})
    settings = _get_system_settings()
    settings['storage_mode'] = mode
    _save_system_settings(settings)
    user_manager.log_activity(username, 'storage_mode_change', 'Storage mode: ' + mode)
    return jsonify({"success": True})


@app.route('/settings/ssh-keygen', methods=['POST'])
def settings_ssh_keygen():
    """Generate SSH key pair. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    key_type = data.get('key_type', 'rsa').strip()
    bits = data.get('bits', '4096').strip()
    passphrase = data.get('passphrase', '')
    key_path = os.path.expanduser('~/.ssh/id_rsa')

    if key_type not in ('rsa', 'ed25519', 'ecdsa'):
        return jsonify({"success": False, "error": "Invalid key type."})

    # If key already exists, don't overwrite
    if os.path.isfile(key_path):
        return jsonify({"success": False, "error": "SSH key already exists at {}. Delete it first if you want to regenerate.".format(key_path)})

    try:
        os.makedirs(os.path.expanduser('~/.ssh'), mode=0o700, exist_ok=True)
        cmd = ['ssh-keygen', '-t', key_type, '-f', key_path, '-N', passphrase]
        if key_type == 'rsa':
            cmd += ['-b', bits]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode != 0:
            return jsonify({"success": False, "error": result.stderr.decode('utf-8', errors='replace')})
        user_manager.log_activity(username, 'ssh_keygen', 'Generated {} key'.format(key_type))
        return jsonify({"success": True, "message": "SSH key generated successfully."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/settings/ssh-copy-id', methods=['POST'])
def settings_ssh_copy_id():
    """Copy SSH public key to remote server. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    remote_ip = data.get('remote_ip', '').strip()
    ssh_user = data.get('ssh_user', 'root').strip() or 'root'
    password = data.get('password', '')

    if not remote_ip:
        return jsonify({"success": False, "error": "Remote IP is required."})
    if not password:
        return jsonify({"success": False, "error": "Password is required for ssh-copy-id."})

    pub_key = os.path.expanduser('~/.ssh/id_rsa.pub')
    if not os.path.isfile(pub_key):
        return jsonify({"success": False, "error": "No SSH public key found. Generate one first."})

    try:
        cmd = [
            'sshpass', '-p', password,
            'ssh-copy-id', '-o', 'StrictHostKeyChecking=no',
            '{}@{}'.format(ssh_user, remote_ip)
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode != 0:
            err = result.stderr.decode('utf-8', errors='replace')
            if 'command not found' in err and 'sshpass' in err:
                return jsonify({"success": False, "error": "sshpass not installed. Run: yum install sshpass"})
            return jsonify({"success": False, "error": err})
        user_manager.log_activity(username, 'ssh_copy_id', 'Copied key to {}@{}'.format(ssh_user, remote_ip))
        return jsonify({"success": True, "message": "SSH key copied successfully to {}@{}.".format(ssh_user, remote_ip)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/settings/test-connection', methods=['POST'])
def settings_test_connection():
    """Test SSH connection to remote server. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    remote_ip = data.get('remote_ip', '').strip()
    ssh_user = data.get('ssh_user', 'root').strip() or 'root'
    if not remote_ip:
        return jsonify({"success": False, "error": "Remote IP is required."})

    try:
        output = _run_remote(['hostname', '&&', 'uptime'], remote_ip, ssh_user)
        return jsonify({"success": True, "output": output.strip()})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Connection timed out.", "hint": "timeout"})
    except Exception as e:
        err = str(e)
        hint = ''
        if 'Permission denied' in err:
            hint = 'permission_denied'
        elif 'No route to host' in err or 'Connection refused' in err:
            hint = 'unreachable'
        elif 'Could not resolve hostname' in err:
            hint = 'dns'
        return jsonify({"success": False, "error": err, "hint": hint})


@app.route('/settings/db', methods=['POST'])
def settings_save_db():
    """Save database connection settings. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    settings = _get_system_settings()
    settings['db'] = {
        'type':     data.get('db_type', 'mariadb').strip(),
        'host':     data.get('host', '127.0.0.1').strip(),
        'port':     int(data.get('port', 3306)),
        'name':     data.get('name', '').strip(),
        'user':     data.get('user', '').strip(),
        'password': data.get('password', '')
    }
    _save_system_settings(settings)
    user_manager.log_activity(username, 'db_config_saved',
                              'Database config saved: {}@{}:{}/{}'.format(
                                  settings['db']['user'], settings['db']['host'],
                                  settings['db']['port'], settings['db']['name']))
    return jsonify({"success": True})


@app.route('/settings/db/test', methods=['POST'])
def settings_test_db():
    """Test database connection. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    db_host = data.get('host', '127.0.0.1').strip()
    db_port = int(data.get('port', 3306))
    db_name = data.get('name', '').strip()
    db_user = data.get('user', '').strip()
    db_pass = data.get('password', '')

    if not db_host or not db_user:
        return jsonify({"success": False, "error": "Host and username are required."})

    try:
        import pymysql
        conn = pymysql.connect(host=db_host, port=db_port, user=db_user,
                               password=db_pass, database=db_name or None,
                               connect_timeout=5)
        cur = conn.cursor()
        cur.execute("SELECT VERSION()")
        version = cur.fetchone()[0]
        cur.execute("SELECT CURRENT_USER()")
        current_user = cur.fetchone()[0]
        cur.close()
        conn.close()
        output = "Server version: {}\nConnected as: {}\nDatabase: {}".format(
            version, current_user, db_name or '(none)')
        return jsonify({"success": True, "output": output})
    except ImportError:
        return jsonify({"success": False, "error": "PyMySQL is not installed. Run: pip install PyMySQL"})
    except Exception as e:
        err = str(e)
        hint = ''
        if 'Access denied' in err:
            hint = 'auth'
        elif 'Can\'t connect' in err or 'Connection refused' in err or 'timed out' in err:
            hint = 'unreachable'
        return jsonify({"success": False, "error": err, "hint": hint})


@app.route('/settings/db/deploy', methods=['POST'])
def settings_deploy_db():
    """Deploy database table structure. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    settings = _get_system_settings()
    db_cfg = settings.get('db', {})
    if not db_cfg.get('host') or not db_cfg.get('user') or not db_cfg.get('name'):
        return jsonify({"success": False, "error": "Database not configured. Save the connection details first."})

    # Order matters: drop dependent tables first, then parent tables
    drop_order = ['activity_log', 'user_config', 'user_projects', 'admin_projects', 'project_status', 'user_pictures', 'users']
    create_order = ['users', 'user_pictures', 'project_status', 'admin_projects', 'user_projects', 'user_config', 'activity_log']

    tables_sql = {
        'users': """
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(100) NOT NULL UNIQUE,
                display_name VARCHAR(200) DEFAULT '',
                is_admin TINYINT(1) DEFAULT 0,
                password_hash VARCHAR(300) DEFAULT '',
                bitbucket_username VARCHAR(200) DEFAULT '',
                bitbucket_password VARCHAR(500) DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        'project_status': """
            CREATE TABLE project_status (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(50) NOT NULL UNIQUE,
                color VARCHAR(30) DEFAULT 'secondary',
                icon VARCHAR(50) DEFAULT 'circle',
                is_default TINYINT(1) DEFAULT 0,
                sort_order INT DEFAULT 0
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        'admin_projects': """
            CREATE TABLE admin_projects (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(200) NOT NULL UNIQUE,
                folder VARCHAR(200) DEFAULT '',
                assigned_to INT NULL,
                status_id INT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_ap_assigned FOREIGN KEY (assigned_to)
                    REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE,
                CONSTRAINT fk_ap_status FOREIGN KEY (status_id)
                    REFERENCES project_status(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        'user_projects': """
            CREATE TABLE user_projects (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                project_id INT NOT NULL,
                status_id INT NULL,
                notes TEXT DEFAULT NULL,
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_user_project (user_id, project_id),
                CONSTRAINT fk_up_user FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE,
                CONSTRAINT fk_up_project FOREIGN KEY (project_id)
                    REFERENCES admin_projects(id) ON DELETE CASCADE ON UPDATE CASCADE,
                CONSTRAINT fk_up_status FOREIGN KEY (status_id)
                    REFERENCES project_status(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        'user_config': """
            CREATE TABLE user_config (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                config_key VARCHAR(100) NOT NULL,
                config_value TEXT DEFAULT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_user_key (user_id, config_key),
                CONSTRAINT fk_uc_user FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        'activity_log': """
            CREATE TABLE activity_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INT NULL,
                username VARCHAR(100) DEFAULT '',
                action VARCHAR(100) DEFAULT '',
                details TEXT DEFAULT NULL,
                INDEX idx_timestamp (timestamp),
                INDEX idx_user_id (user_id),
                CONSTRAINT fk_al_user FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE SET NULL ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """,
        'user_pictures': """
            CREATE TABLE user_pictures (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL UNIQUE,
                picture_data MEDIUMBLOB NOT NULL,
                mime_type VARCHAR(50) DEFAULT 'image/jpeg',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                CONSTRAINT fk_pic_user FOREIGN KEY (user_id)
                    REFERENCES users(id) ON DELETE CASCADE ON UPDATE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    }

    # Default project statuses (cannot be deleted by users)
    default_statuses = [
        ('DONE', 'success', 'check-circle', 1, 1),
        ('NOT OK', 'danger', 'x-circle', 1, 2),
        ('IDLE', 'warning', 'pause-circle', 1, 3),
        ('WIP', 'primary', 'loader', 1, 4),
    ]

    try:
        import pymysql
        conn = pymysql.connect(
            host=db_cfg['host'], port=int(db_cfg.get('port', 3306)),
            user=db_cfg['user'], password=db_cfg.get('password', ''),
            database=db_cfg['name'], connect_timeout=5
        )
        cur = conn.cursor()

        # Drop all existing tables first
        cur.execute("SET FOREIGN_KEY_CHECKS = 0")
        for table_name in drop_order:
            try:
                cur.execute("DROP TABLE IF EXISTS `%s`" % table_name)
            except Exception:
                pass
        # Also drop legacy 'projects' table if it exists from older schema
        try:
            cur.execute("DROP TABLE IF EXISTS projects")
        except Exception:
            pass
        cur.execute("SET FOREIGN_KEY_CHECKS = 1")

        # Create tables in order
        results = []
        for table_name in create_order:
            ddl = tables_sql[table_name]
            try:
                cur.execute(ddl)
                results.append({'name': table_name, 'status': 'Created'})
            except Exception as te:
                results.append({'name': table_name, 'status': 'Error: ' + str(te)})

        # Insert default project statuses
        for s_name, s_color, s_icon, s_default, s_order in default_statuses:
            try:
                cur.execute(
                    "INSERT INTO project_status (name, color, icon, is_default, sort_order) "
                    "VALUES (%s, %s, %s, %s, %s)",
                    (s_name, s_color, s_icon, s_default, s_order)
                )
            except Exception:
                pass

        conn.commit()
        cur.close()
        conn.close()

        user_manager.log_activity(username, 'db_deploy', 'Database structure deployed')
        return jsonify({
            "success": True,
            "message": "Database structure deployed successfully.",
            "tables": results
        })
    except ImportError:
        return jsonify({"success": False, "error": "PyMySQL is not installed. Run: pip install PyMySQL"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route('/settings/db/migrate', methods=['POST'])
def settings_migrate_db():
    """Migrate data from JSON files to the database. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    settings = _get_system_settings()
    db_cfg = settings.get('db', {})
    if not db_cfg.get('host') or not db_cfg.get('user') or not db_cfg.get('name'):
        return jsonify({"success": False, "error": "Database not configured."})

    try:
        import pymysql
        conn = pymysql.connect(
            host=db_cfg['host'], port=int(db_cfg.get('port', 3306)),
            user=db_cfg['user'], password=db_cfg.get('password', ''),
            database=db_cfg['name'], connect_timeout=10
        )
        cur = conn.cursor()
        migrated = []

        # Build status name mapping: old lowercase key → uppercase name in project_status
        _status_name_map = {
            'done': 'DONE', 'not_ok': 'NOT OK', 'idle': 'IDLE', 'wip': 'WIP'
        }

        # 1. Migrate master projects → admin_projects
        base_dir = user_manager._get_base_dir()
        master_path = os.path.join(base_dir, 'master_projects.json')
        master_projects = []
        notes_by_project = {}
        if os.path.isfile(master_path):
            with open(master_path, 'r') as f:
                master_projects = json.load(f)
            count = 0
            for p in master_projects:
                pname = p.get('name', '')
                notes_by_project[pname] = p.get('notes', '')
                try:
                    cur.execute(
                        "INSERT INTO admin_projects (name, folder) VALUES (%s, %s) "
                        "ON DUPLICATE KEY UPDATE folder=VALUES(folder)",
                        (pname, p.get('folder', ''))
                    )
                    count += 1
                except Exception:
                    pass
            migrated.append({'name': 'admin_projects', 'count': count})

        # 2. Migrate admin list + user configs → users table
        admin_path = os.path.join(base_dir, 'admin.json')
        admin_list = []
        if os.path.isfile(admin_path):
            with open(admin_path, 'r') as f:
                admin_data = json.load(f)
            admin_list = admin_data.get('admins', [])

        # Collect all known usernames from admin list, projects, and user config files
        all_usernames = set(admin_list)
        projects_path = os.path.join(base_dir, 'projects.json')
        projects_data = {}
        if os.path.isfile(projects_path):
            with open(projects_path, 'r') as f:
                projects_data = json.load(f).get('assignments', {})
            all_usernames.update(projects_data.keys())

        users_dir = os.path.join(base_dir, 'users')
        if os.path.isdir(users_dir):
            for fname in os.listdir(users_dir):
                if fname.endswith('.json'):
                    all_usernames.add(fname[:-5])

        user_count = 0
        config_count = 0
        for uname in all_usernames:
            is_admin_flag = 1 if uname in admin_list else 0
            display_name = ''
            bb_user = ''
            bb_pass = ''

            # Try to read user config file
            user_cfg_path = os.path.join(users_dir, uname + '.json')
            if os.path.isfile(user_cfg_path):
                try:
                    with open(user_cfg_path, 'r') as f:
                        ucfg = json.load(f)
                    display_name = ucfg.get('display_name', '')
                    bb_user = ucfg.get('bitbucket_username', '')
                    bb_pass = ucfg.get('bitbucket_password', '')
                except Exception:
                    pass

            # Also check display_name from projects.json assignments
            if not display_name and uname in projects_data:
                display_name = projects_data[uname].get('display_name', '')

            try:
                cur.execute(
                    "INSERT INTO users (username, display_name, is_admin, bitbucket_username, bitbucket_password) "
                    "VALUES (%s, %s, %s, %s, %s) "
                    "ON DUPLICATE KEY UPDATE display_name=VALUES(display_name), is_admin=VALUES(is_admin), "
                    "bitbucket_username=VALUES(bitbucket_username), bitbucket_password=VALUES(bitbucket_password)",
                    (uname, display_name, is_admin_flag, bb_user, bb_pass)
                )
                user_count += 1
            except Exception:
                pass

            # Migrate user config to user_config table (FK: user_id)
            if os.path.isfile(user_cfg_path):
                try:
                    with open(user_cfg_path, 'r') as f:
                        ucfg = json.load(f)
                    skip_keys = {'username', 'display_name', 'bitbucket_username', 'bitbucket_password'}
                    for ckey, cval in ucfg.items():
                        if ckey in skip_keys:
                            continue
                        cur.execute(
                            "INSERT INTO user_config (user_id, config_key, config_value) "
                            "SELECT id, %s, %s FROM users WHERE username=%s "
                            "ON DUPLICATE KEY UPDATE config_value=VALUES(config_value)",
                            (ckey, str(cval), uname)
                        )
                        config_count += 1
                except Exception:
                    pass

        migrated.append({'name': 'users', 'count': user_count})
        migrated.append({'name': 'user_config', 'count': config_count})

        # 3. Migrate user-project assignments (user_id + project_id + status_id via FK)
        assign_count = 0
        for uname, udata in projects_data.items():
            for proj in udata.get('projects', []):
                proj_name = proj.get('name', '')
                proj_notes = notes_by_project.get(proj_name, '')
                old_status = proj.get('status', 'idle')
                new_status_name = _status_name_map.get(old_status, 'IDLE')
                try:
                    cur.execute(
                        "INSERT INTO user_projects (user_id, project_id, status_id, notes) "
                        "SELECT u.id, ap.id, ps.id, %s "
                        "FROM users u "
                        "JOIN admin_projects ap ON ap.name = %s "
                        "JOIN project_status ps ON ps.name = %s "
                        "WHERE u.username = %s "
                        "ON DUPLICATE KEY UPDATE status_id=VALUES(status_id), notes=VALUES(notes)",
                        (proj_notes, proj_name, new_status_name, uname)
                    )
                    assign_count += 1
                except Exception:
                    pass
        migrated.append({'name': 'user_projects', 'count': assign_count})

        # 3b. Update admin_projects with assigned_to and status_id from user_projects
        try:
            cur.execute(
                "UPDATE admin_projects ap "
                "JOIN user_projects up ON up.project_id = ap.id "
                "SET ap.assigned_to = up.user_id, ap.status_id = up.status_id"
            )
        except Exception:
            pass

        # 4. Migrate activity log
        log_path = os.path.join(base_dir, 'activity.log')
        log_count = 0
        if os.path.isfile(log_path):
            with open(log_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        log_user = entry.get('username', '')
                        cur.execute(
                            "INSERT INTO activity_log (user_id, username, action, details, timestamp) "
                            "VALUES ((SELECT id FROM users WHERE username=%s LIMIT 1), %s, %s, %s, %s)",
                            (log_user, log_user, entry.get('action', ''),
                             entry.get('details', ''), entry.get('timestamp', None))
                        )
                        log_count += 1
                    except Exception:
                        pass
        migrated.append({'name': 'activity_log', 'count': log_count})

        conn.commit()
        cur.close()
        conn.close()

        user_manager.log_activity(username, 'db_migrate', 'Data migrated to database')
        return jsonify({"success": True, "message": "Data migration completed.", "migrated": migrated})
    except ImportError:
        return jsonify({"success": False, "error": "PyMySQL is not installed."})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ============================================================
# Project Status endpoints
# ============================================================

@app.route('/settings/project-statuses', methods=['GET'])
def settings_get_project_statuses():
    """Get all project statuses from DB."""
    statuses = _db_get_all_statuses()
    return jsonify({"success": True, "statuses": statuses})


@app.route('/settings/project-statuses/add', methods=['POST'])
def settings_add_project_status():
    """Add a new project status. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    name = data.get('name', '').strip().upper()
    color = data.get('color', 'secondary').strip()
    icon = data.get('icon', 'circle').strip()
    if not name:
        return jsonify({"success": False, "error": "Status name is required."})
    conn = _db_connect()
    if not conn:
        return jsonify({"success": False, "error": "DB not available."})
    try:
        cur = conn.cursor()
        cur.execute("SELECT COALESCE(MAX(sort_order),0)+1 AS next_order FROM project_status")
        next_order = cur.fetchone()['next_order']
        cur.execute(
            "INSERT INTO project_status (name, color, icon, is_default, sort_order) "
            "VALUES (%s, %s, %s, 0, %s)",
            (name, color, icon, next_order)
        )
        _log_activity(username, 'add_status', 'Added project status: %s' % name)
        return jsonify({"success": True})
    except Exception as e:
        err = str(e)
        if 'Duplicate' in err:
            return jsonify({"success": False, "error": "Status '%s' already exists." % name})
        return jsonify({"success": False, "error": err})
    finally:
        conn.close()


@app.route('/settings/project-statuses/update', methods=['POST'])
def settings_update_project_status():
    """Update a project status (name, color, icon). Cannot rename defaults. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    status_id = data.get('id')
    new_name = data.get('name', '').strip().upper()
    new_color = data.get('color', 'secondary').strip()
    new_icon = data.get('icon', 'circle').strip()
    if not status_id or not new_name:
        return jsonify({"success": False, "error": "ID and name are required."})
    conn = _db_connect()
    if not conn:
        return jsonify({"success": False, "error": "DB not available."})
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE project_status SET name=%s, color=%s, icon=%s WHERE id=%s",
            (new_name, new_color, new_icon, status_id)
        )
        _log_activity(username, 'update_status', 'Updated project status id=%s to %s' % (status_id, new_name))
        return jsonify({"success": True})
    except Exception as e:
        err = str(e)
        if 'Duplicate' in err:
            return jsonify({"success": False, "error": "Status '%s' already exists." % new_name})
        return jsonify({"success": False, "error": err})
    finally:
        conn.close()


@app.route('/settings/project-statuses/delete', methods=['POST'])
def settings_delete_project_status():
    """Delete a custom project status. Cannot delete default ones. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    status_id = data.get('id')
    if not status_id:
        return jsonify({"success": False, "error": "Status ID is required."})
    conn = _db_connect()
    if not conn:
        return jsonify({"success": False, "error": "DB not available."})
    try:
        cur = conn.cursor()
        cur.execute("SELECT name, is_default FROM project_status WHERE id=%s", (status_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"success": False, "error": "Status not found."})
        if row['is_default']:
            return jsonify({"success": False, "error": "Cannot delete default status '%s'." % row['name']})
        cur.execute("DELETE FROM project_status WHERE id=%s", (status_id,))
        _log_activity(username, 'delete_status', 'Deleted project status: %s' % row['name'])
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
    finally:
        conn.close()


@app.route('/settings/auth', methods=['GET'])
def settings_get_auth():
    """Get authentication settings. Admin only."""
    username = request.args.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403
    settings = _get_system_settings()
    auth = settings.get('auth', {'method': 'system', 'sso': {}})
    return jsonify({"success": True, "auth": auth})


@app.route('/settings/auth', methods=['POST'])
def settings_save_auth():
    """Save authentication settings. Admin only."""
    data = request.get_json()
    username = data.get('username', '').strip()
    if not user_manager.is_admin(username):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    method = data.get('method', 'system').strip()
    if method not in ('system', 'database', 'sso'):
        return jsonify({"success": False, "error": "Invalid auth method."})

    settings = _get_system_settings()
    settings['auth'] = {
        'method': method,
        'sso': {
            'provider':      data.get('sso_provider', '').strip(),
            'client_id':     data.get('sso_client_id', '').strip(),
            'client_secret': data.get('sso_client_secret', '').strip(),
            'issuer_url':    data.get('sso_issuer_url', '').strip(),
            'redirect_uri':  data.get('sso_redirect_uri', '').strip()
        }
    }
    _save_system_settings(settings)
    user_manager.log_activity(username, 'auth_config_saved', 'Auth method: ' + method)
    return jsonify({"success": True})


# End Settings endpoints
# ============================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)