import os
import sys

from pathlib import Path

# Add the project root to the python path so we can import app.py
root_dir = Path(__file__).parent.parent
sys.path.append(str(root_dir))

try:
    from app import create_app
    app = create_app()
except Exception as e:
    from flask import Flask
    app = Flask(__name__)
    @app.route('/')
    @app.route('/<path:path>')
    def error(path=None):
        import traceback
        return f"Error during app initialization: {str(e)}<br><pre>{traceback.format_exc()}</pre>", 500
