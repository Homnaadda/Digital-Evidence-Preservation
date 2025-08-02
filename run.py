#!/usr/bin/env python3
"""
Digital Evidence Management System
Main application entry point
"""

import os
from app import create_app

# Create Flask application
app = create_app()

if __name__ == '__main__':
    # Get configuration from environment
    debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '127.0.0.1')
    port = int(os.environ.get('FLASK_PORT', 5000))
    
    print("🔐 Digital Evidence Management System")
    print("=" * 50)
    print(f"🌐 Server: http://{host}:{port}")
    print(f"🔧 Debug Mode: {debug}")
    print("=" * 50)
    print("📋 Default Admin Credentials:")
    print("   Username: admin")
    print("   Password: admin123")
    print("⚠️  Change default credentials in production!")
    print("=" * 50)
    
    # Run the application
    app.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )