import os
import sys

from pathlib import Path

# Get the absolute path of the project root
# __file__ is .../api/index.py
# parent is .../api
# parent.parent is .../ (root)
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.append(str(BASE_DIR))

try:
    from app import create_app
    app = create_app()
    
    @app.route('/test-vercel')
    def test_vercel():
        return "Vercel is working! Flask app is running."
        
except Exception as e:
    from flask import Flask
    import traceback
    app = Flask(__name__)
    @app.route('/')
    @app.route('/<path:path>')
    def catch_all(path=None):
        return f"<h1>Startup Error</h1><pre>{traceback.format_exc()}</pre>", 500
