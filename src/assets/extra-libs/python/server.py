import os
import sys
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

# Global variable to store the running process
current_process = None

@app.route('/search-roles')
def search_roles():
    try:
        config = config_loader.load_config()
        base_route  = config['search']['base_route']
        folder_name = config['search']['folder_name']

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
                ['ansible-playbook', playbook_path],
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
        engineers = builds_scanner.get_engineers_summary(data["projects"])
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

# All above this is endpoints, do not delete the lines below
if __name__ == '__main__':
    app.run(port=5000)