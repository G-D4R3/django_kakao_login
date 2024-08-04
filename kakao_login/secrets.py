import json
import os

SECRET_PATH = os.path.dirname(os.path.abspath(__file__))
ENV_MODE = 'local'

def get_secrets(key):
    try:
        value = os.environ[key]
        return value
    except KeyError as e:
        if ENV_MODE != 'local':
            raise e
    secrets = json.loads(open(os.path.join(SECRET_PATH, 'secrets.json')).read())
    return secrets[key]