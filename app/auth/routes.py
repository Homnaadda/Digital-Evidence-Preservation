from flask import render_template, redirect, url_for, flash, request, current_app
from flask_login import login_user, logout_user, current_user
from app.auth import bp
from app.models import User, SystemLog
from app import db
from datetime import datetime

@bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login route"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        if not username or not password:
            flash('Please provide both username and password.', 'error')
            return render_template('auth/login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password) and user.is_active:
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            # Log successful login
            log_entry = SystemLog(
                user_id=user.id,
                action='login',
                details=f'Successful login for user {username}',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(log_entry)
            db.session.commit()
            
            login_user(user, remember=remember)
            
            # Redirect to appropriate dashboard based on role
            next_page = request.args.get('next')
            if not next_page or not next_page.startswith('/'):
                if user.is_admin():
                    next_page = url_for('admin.dashboard')
                elif user.is_forensic():
                    next_page = url_for('main.forensic_dashboard')
                else:
                    next_page = url_for('main.police_dashboard')
            
            flash(f'Welcome back, {user.full_name}!', 'success')
            return redirect(next_page)
        else:
            # Log failed login attempt
            log_entry = SystemLog(
                action='failed_login',
                details=f'Failed login attempt for username: {username}',
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(log_entry)
            db.session.commit()
            
            flash('Invalid username or password.', 'error')
    
    return render_template('auth/login.html')

@bp.route('/logout')
def logout():
    """User logout route"""
    if current_user.is_authenticated:
        # Log logout
        log_entry = SystemLog(
            user_id=current_user.id,
            action='logout',
            details=f'User {current_user.username} logged out',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log_entry)
        db.session.commit()
        
        flash('You have been logged out successfully.', 'info')
    
    logout_user()
    return redirect(url_for('auth.login'))