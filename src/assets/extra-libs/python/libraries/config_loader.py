import configparser
import os

def find_project_root():
    """Walk up from this file's location until a directory containing README.md is found."""
    current = os.path.dirname(os.path.abspath(__file__))
    while True:
        if os.path.exists(os.path.join(current, 'README.md')):
            return current
        parent = os.path.dirname(current)
        if parent == current:  # reached filesystem root without finding README.md
            return os.path.dirname(os.path.abspath(__file__))
        current = parent

def load_config():
    project_root = find_project_root()
    config = configparser.ConfigParser(defaults={'project_root': project_root})
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.conf')
    config.read(config_path)
    return config