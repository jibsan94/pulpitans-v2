import os
import sys
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libraries')
sys.path.insert(0, script_dir)

import path_finder
import make_yaml
import config_loader

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

@app.route('/make-build', methods=['POST'])
def make_build():
    try:
        data = request.get_json()
        selected_role = data.get('role', '')

        if not selected_role:
            return jsonify({"success": False, "error": "No role selected."})

        config = config_loader.load_config()
        output_path = os.path.join(config['build']['output_path'], 'build.yaml')

        # Pass all form data to make_yaml
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

if __name__ == '__main__':
    app.run(port=5000)