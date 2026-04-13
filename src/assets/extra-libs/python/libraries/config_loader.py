import configparser
import os

def load_config():
    config = configparser.ConfigParser()
    # Goes up from libraries/ to html/ where config.conf is
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.conf')
    config.read(config_path)
    return config