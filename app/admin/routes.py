from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from app.admin import bp
from app.models import User, Evidence, Case, SystemLog, ChainOfCustody
from app import db
from datetime import datetime, timedelta
from sqlalchemy import func

@bp.route('/dashboard')
@login_required
def dashboard():
    """Admin dashboard"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # System statistics
    total_users = User.query.count()
    total_evidence = Evidence.query.count()
    total_cases = Case.query.count()
    pending_analysis = Evidence.query.filter_by(status='submitted').count()
    
    # Recent activity
    recent_logs = SystemLog.query.order_by(
        SystemLog.timestamp.desc()
    ).limit(10).all()
    
    # User statistics by role
    user_stats = db.session.query(
        User.role, func.count(User.id)
    ).group_by(User.role).all()
    
    # Evidence statistics by status
    evidence_stats = db.session.query(
        Evidence.status, func.count(Evidence.id)
    ).group_by(Evidence.status).all()
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_evidence=total_evidence,
                         total_cases=total_cases,
                         pending_analysis=pending_analysis,
                         recent_logs=recent_logs,
                         user_stats=user_stats,
                         evidence_stats=evidence_stats)

@bp.route('/users')
@login_required
def manage_users():
    """User management page"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 15
    
    users_pagination = User.query.order_by(
        User.created_at.desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/manage_users.html',
                         users=users_pagination.items,
                         pagination=users_pagination)

@bp.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    """Add new user"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        full_name = request.form.get('full_name')
        badge_number = request.form.get('badge_number')
        department = request.form.get('department')
        
        # Validate required fields
        if not all([username, email, password, role, full_name]):
            flash('Please fill in all required fields.', 'error')
            return render_template('admin/add_user.html')
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return render_template('admin/add_user.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists.', 'error')
            return render_template('admin/add_user.html')
        
        # Create new user
        user = User(
            username=username,
            email=email,
            role=role,
            full_name=full_name,
            badge_number=badge_number,
            department=department
        )
        user.set_password(password)
        
        db.session.add(user)
        
        # Log the action
        log_entry = SystemLog(
            user_id=current_user.id,
            action='user_created',
            resource=f'User {username}',
            details=f'New user created with role: {role}',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log_entry)
        
        db.session.commit()
        
        flash(f'User {username} has been created successfully!', 'success')
        return redirect(url_for('admin.manage_users'))
    
    return render_template('admin/add_user.html')

@bp.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    """Delete user"""
    if not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting self
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    
    # Prevent deleting admin users (optional safety measure)
    if user.is_admin():
        return jsonify({'error': 'Cannot delete admin users'}), 400
    
    username = user.username
    
    # Deactivate instead of delete to preserve data integrity
    user.is_active = False
    
    # Log the action
    log_entry = SystemLog(
        user_id=current_user.id,
        action='user_deactivated',
        resource=f'User {username}',
        details=f'User account deactivated',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(log_entry)
    
    db.session.commit()
    
    return jsonify({'success': f'User {username} has been deactivated'})

@bp.route('/users/toggle-status/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    """Toggle user active status"""
    if not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    user = User.query.get_or_404(user_id)
    
    # Prevent modifying self
    if user.id == current_user.id:
        return jsonify({'error': 'Cannot modify your own account status'}), 400
    
    user.is_active = not user.is_active
    status = 'activated' if user.is_active else 'deactivated'
    
    # Log the action
    log_entry = SystemLog(
        user_id=current_user.id,
        action=f'user_{status}',
        resource=f'User {user.username}',
        details=f'User account {status}',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(log_entry)
    
    db.session.commit()
    
    return jsonify({'success': f'User {user.username} has been {status}'})

@bp.route('/logs')
@login_required
def system_logs():
    """View system logs"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Filter options
    action_filter = request.args.get('action')
    user_filter = request.args.get('user_id', type=int)
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    logs_query = SystemLog.query
    
    if action_filter:
        logs_query = logs_query.filter(SystemLog.action.contains(action_filter))
    
    if user_filter:
        logs_query = logs_query.filter_by(user_id=user_filter)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            logs_query = logs_query.filter(SystemLog.timestamp >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            logs_query = logs_query.filter(SystemLog.timestamp < date_to_obj)
        except ValueError:
            pass
    
    logs_pagination = logs_query.order_by(
        SystemLog.timestamp.desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get unique actions for filter dropdown
    unique_actions = db.session.query(SystemLog.action).distinct().all()
    actions = [action[0] for action in unique_actions]
    
    # Get users for filter dropdown
    users = User.query.order_by(User.full_name).all()
    
    return render_template('admin/system_logs.html',
                         logs=logs_pagination.items,
                         pagination=logs_pagination,
                         actions=actions,
                         users=users,
                         current_filters={
                             'action': action_filter,
                             'user_id': user_filter,
                             'date_from': date_from,
                             'date_to': date_to
                         })

@bp.route('/reports')
@login_required
def reports():
    """System reports and analytics"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Date range for reports (last 30 days by default)
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    
    # Evidence submission trends
    evidence_by_date = db.session.query(
        func.date(Evidence.submitted_at).label('date'),
        func.count(Evidence.id).label('count')
    ).filter(
        Evidence.submitted_at >= start_date
    ).group_by(
        func.date(Evidence.submitted_at)
    ).order_by('date').all()
    
    # User activity
    user_activity = db.session.query(
        User.full_name,
        func.count(SystemLog.id).label('activity_count')
    ).join(
        SystemLog, User.id == SystemLog.user_id
    ).filter(
        SystemLog.timestamp >= start_date
    ).group_by(
        User.id, User.full_name
    ).order_by('activity_count desc').limit(10).all()
    
    # Evidence by type
    evidence_by_type = db.session.query(
        Evidence.evidence_type,
        func.count(Evidence.id).label('count')
    ).group_by(Evidence.evidence_type).all()
    
    return render_template('admin/reports.html',
                         evidence_by_date=evidence_by_date,
                         user_activity=user_activity,
                         evidence_by_type=evidence_by_type,
                         start_date=start_date,
                         end_date=end_date)