import os
import sys
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# server.py está en src/html/, assets está en src/assets/
# por eso subimos un nivel con ..
script_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'assets', 'extra-libs', 'python')
sys.path.insert(0, script_dir)

import path_finder

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

if __name__ == '__main__':
    app.run(port=5000)