import os
import sys
from flask import Flask, jsonify, request
from flask_cors import CORS
import configparser

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

        make_yaml.generate_build_yaml(selected_role, output_path)

        return jsonify({"success": True, "error": "", "path": output_path})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    app.run(port=5000)