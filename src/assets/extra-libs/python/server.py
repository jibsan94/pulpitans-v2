import os
import sys
import re
import json
import signal
import shutil
import tarfile
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

# Global variable to store the running process
current_process = None

# ============================================================
# Auth / User endpoints
# ============================================================

@app.route('/auth/users')
def auth_list_users():
    """Return the list of managed users (those in projects.json) available for login."""
    try:
        assignments = user_manager.get_all_projects()
        users = sorted(assignments.keys())
        return jsonify({"success": True, "users": users})
    except Exception as e:
        return jsonify({"success": True, "users": []})


@app.route('/auth/login', methods=['POST'])
def auth_login():
    """Validate username + password via PAM and return profile."""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username:
            return jsonify({"success": False, "error": "Username is required."})

        if not password:
            return jsonify({"success": False, "error": "Password is required."})

        if not re.match(r'^[a-zA-Z0-9_.\-]+$', username):
            return jsonify({"success": False, "error": "Invalid username."})

        if not user_manager.validate_username(username):
            return jsonify({"success": False, "error": f"User '{username}' does not exist on this system."})

        # Check user is in the managed list (projects.json)
        assignments = user_manager.get_all_projects()
        if username not in assignments:
            return jsonify({"success": False, "error": "User is not enabled. Contact an administrator."})
        # Authenticate against PAM (system password)
        import pam
        p = pam.pam()
        if not p.authenticate(username, password):
            return jsonify({"success": False, "error": "Incorrect password."})

        cfg = user_manager.get_user_config(username)

        # Log the login activity
        user_manager.log_activity(username, 'login', 'User logged in')

        return jsonify({
            "success": True,
            "username": username,
            "display_name": cfg.get('display_name', '') or username,
            "is_admin": user_manager.is_admin(username)
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

        cfg = user_manager.get_user_config(username)
        cfg['display_name'] = display_name

        # BitBucket credentials (optional)
        if 'bitbucket_username' in data:
            cfg['bitbucket_username'] = data['bitbucket_username'].strip()
        if 'bitbucket_password' in data:
            cfg['bitbucket_password'] = data['bitbucket_password']

        user_manager.save_user_config(username, cfg)

        return jsonify({
            "success": True,
            "display_name": display_name or username
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

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

            display_name = info.get('display_name', username)
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
        # --- Memory ---
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

        # --- Disk /iDASREPO ---
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
    entries = user_manager.get_activity_log(limit=limit, username_filter=user_filter)
    return jsonify({"success": True, "entries": entries})


@app.route('/admin/projects', methods=['GET'])
def admin_get_projects():
    """Returns all project assignments."""
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

    ok, msg = user_manager.move_project(project_name, from_user, to_user)
    if ok:
        user_manager.log_activity(admin_user, 'move_project',
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

    ok, msg = user_manager.set_project_status(username, project_name, status)
    if ok:
        user_manager.log_activity(admin_user, 'set_project_status',
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

    ok, msg = user_manager.add_project(username, project_name, status)
    if ok:
        user_manager.log_activity(admin_user, 'add_project',
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

    ok, msg = user_manager.remove_project(username, project_name)
    if ok:
        user_manager.log_activity(admin_user, 'remove_project',
            f'Removed {project_name} from {username}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/projects/available', methods=['GET'])
def admin_available_projects():
    """Returns the list of master projects not yet assigned to any user."""
    available = user_manager.get_available_projects()
    return jsonify({"success": True, "projects": available})


@app.route('/admin/projects/master', methods=['GET'])
def admin_master_projects():
    """Returns all master projects with their assignment info."""
    master = user_manager.get_master_projects()
    result = []
    for p in master:
        assigned_to, status = user_manager.get_project_assignment(p['name'])
        result.append({
            "name": p['name'],
            "folder": p['folder'],
            "assigned_to": assigned_to or '',
            "status": status or ''
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

    ok, msg = user_manager.update_master_project(old_name, new_name, new_folder)
    if ok:
        user_manager.log_activity(admin_user, 'update_project', f'Updated project {old_name} → {new_name} (folder: {new_folder})')
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

    ok, msg = user_manager.delete_master_project(name)
    if ok:
        user_manager.log_activity(admin_user, 'delete_project', f'Deleted project {name}')
    return jsonify({"success": ok, "error": "" if ok else msg})


@app.route('/admin/users', methods=['GET'])
def admin_list_managed_users():
    """List only managed users (those in projects.json)."""
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

    user_manager.set_admin(target_user, make_admin)
    action = 'grant_admin' if make_admin else 'revoke_admin'
    user_manager.log_activity(admin_user, action, f'{action} for {target_user}')
    return jsonify({"success": True})


@app.route('/admin/users/add-to-list', methods=['POST'])
def admin_add_user_to_list():
    """Add a system user to the managed users list. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    target_user = data.get('username', '').strip()
    user_manager.add_user_to_projects(target_user)
    user_manager.log_activity(admin_user, 'add_user_to_list', f'Added {target_user} to managed users')
    return jsonify({"success": True})


@app.route('/admin/users/remove-from-list', methods=['POST'])
def admin_remove_user_from_list():
    """Remove a user from the managed users list. Admin only."""
    data = request.get_json()
    admin_user = data.get('admin_username', '').strip()
    if not user_manager.is_admin(admin_user):
        return jsonify({"success": False, "error": "Unauthorized."}), 403

    target_user = data.get('username', '').strip()
    user_manager.remove_user_from_projects(target_user)
    user_manager.log_activity(admin_user, 'remove_user_from_list', f'Removed {target_user} from managed users')
    return jsonify({"success": True})

# End Admin endpoints
# ============================================================

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)