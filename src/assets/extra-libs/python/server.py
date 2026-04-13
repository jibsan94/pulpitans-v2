import os
import sys
import subprocess
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libraries')
sys.path.insert(0, script_dir)

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

if __name__ == '__main__':
    app.run(port=5000)