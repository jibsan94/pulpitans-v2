import os
import sys
import yaml
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'libraries')
sys.path.insert(0, script_dir)

import path_finder
import make_yaml  # importa el nuevo módulo

@app.route('/search-roles')
def search_roles():
    try:
        routes = path_finder.search_folder("idas_tool_mkbuild", "/home")
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

        output_path = os.path.join(script_dir, 'build.yaml')

        # Delegates the YAML generation to make_yaml.py
        make_yaml.generate_build_yaml(selected_role, output_path)

        return jsonify({"success": True, "error": "", "path": output_path})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

if __name__ == '__main__':
    app.run(port=5000)