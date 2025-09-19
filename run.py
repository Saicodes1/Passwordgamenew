#!/usr/bin/env python3
"""
ACM BPDC Password Game - Production Startup Script
Run this script to start the password game server
"""

import sys
import os
from sqlalchemy import inspect, text
from app import app, db, User, bcrypt

def setup_database():
    """Initialize database and create admin user if needed"""
    try:
        with app.app_context():
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully")

            # --- Check if `full_name` column exists, add if missing ---
            inspector = inspect(db.engine)
            columns = [col['name'] for col in inspector.get_columns('user')]
            if "full_name" not in columns:
                with db.engine.connect() as conn:
                    conn.execute(text("ALTER TABLE user ADD COLUMN full_name VARCHAR(120)"))
                    conn.commit()
                print("✅ Added missing 'full_name' column to user table")

            # Check if admin user exists
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
                admin_user = User(
                    username='admin',
                    email='admin@passwordgame.com',
                    password_hash=admin_password,
                    is_admin=True,
                    full_name="Administrator"
                )
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Admin user created (username: admin, password: admin123)")
            else:
                print("✅ Admin user already exists")

    except Exception as e:
        print(f"❌ Database setup failed: {e}")
        return False
    return True

def main():
    """Main startup function"""
    print("🎮 ACM BPDC Password Game Starting...")
    print("=" * 50)
    
    # Setup database
    if not setup_database():
        sys.exit(1)
    
    # Start the server
    print("\n🚀 Starting Flask server...")
    print("📍 Game URL: http://127.0.0.1:5000")
    print("👑 Admin Panel: http://127.0.0.1:5000/admin")
    print("🔑 Admin Login: admin / admin123")
    print("\n⚠️  REMEMBER: Change admin password in production!")
    print("=" * 50)
    
    try:
        app.run(host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n👋 Server stopped by user")
    except Exception as e:
        print(f"❌ Server error: {e}")

if __name__ == "__main__":
    main()
