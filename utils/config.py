import json
import os

class ConfigLoader:
    _config = {
        "database": {
            "db_name": "test_db",
            "host": "localhost",
            "user": "root",
            "password": ""
        }
    }

    @classmethod
    def get(cls, key):
        return cls._config.get(key, {})
    
    @classmethod
    def load(cls, filepath="config.json"):
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                try:
                    cls._config.update(json.load(f))
                except json.JSONDecodeError:
                    pass
