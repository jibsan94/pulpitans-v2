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

@app.route('/buscar-roles')
def buscar_roles():
    try:
        rutas = path_finder.buscar_carpeta("idas_tool_mkbuild", "/home")
        return jsonify({
            "rutas": rutas,
            "error": ""
        })
    except Exception as e:
        return jsonify({
            "rutas": [],
            "error": str(e)
        })

if __name__ == '__main__':
    app.run(port=5000)