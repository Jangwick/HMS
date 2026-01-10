import os
import sys

# Add the project root to the python path so we can import app.py
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app import create_app

# This is the entry point for Vercel
app = create_app()
