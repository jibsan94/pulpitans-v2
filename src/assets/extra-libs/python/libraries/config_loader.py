import configparser
import os

# This file lives at: <project_root>/src/assets/extra-libs/python/libraries/config_loader.py
# Project root is always 5 levels up from here, regardless of where the project is deployed.
_LIBRARIES_DIR  = os.path.dirname(os.path.abspath(__file__))
_PYTHON_DIR     = os.path.dirname(_LIBRARIES_DIR)
_EXTRA_LIBS_DIR = os.path.dirname(_PYTHON_DIR)
_ASSETS_DIR     = os.path.dirname(_EXTRA_LIBS_DIR)
_SRC_DIR        = os.path.dirname(_ASSETS_DIR)
PROJECT_ROOT    = os.path.dirname(_SRC_DIR)

def load_config():
    config = configparser.ConfigParser(defaults={'project_root': PROJECT_ROOT})
    config_path = os.path.join(_PYTHON_DIR, 'config.conf')
    config.read(config_path)
    return config