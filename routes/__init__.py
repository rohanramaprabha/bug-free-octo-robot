# routes/__init__.py
from .main_routes import main_bp
from .scan_routes import scan_bp
from .api_routes import api_bp

__all__ = ["main_bp", "scan_bp", "api_bp"]
