from flask import render_template, redirect, url_for, current_app
from flask_login import login_required, current_user
from app.main import bp
from app.models import Evidence, Case, User, SystemLog
from app import db
from sqlalchemy import func

@bp.route('/')
def index():
    """Home page - redirect to appropriate dashboard"""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))

@bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard - route to role-specific dashboard"""
    if current_user.is_admin():
        return redirect(url_for('admin.dashboard'))
    elif current_user.is_forensic():
        return redirect(url_for('main.forensic_dashboard'))
    else:
        return redirect(url_for('main.police_dashboard'))

@bp.route('/police-dashboard')
@login_required
def police_dashboard():
    """Police officer dashboard"""
    if not current_user.is_police():
        return redirect(url_for('main.dashboard'))
    
    # Get statistics for the current user
    total_evidence = Evidence.query.filter_by(submitted_by=current_user.id).count()
    pending_evidence = Evidence.query.filter_by(
        submitted_by=current_user.id, 
        status='submitted'
    ).count()
    analyzed_evidence = Evidence.query.filter_by(
        submitted_by=current_user.id, 
        status='analyzed'
    ).count()
    
    # Recent evidence submitted by this user
    recent_evidence = Evidence.query.filter_by(
        submitted_by=current_user.id
    ).order_by(Evidence.submitted_at.desc()).limit(5).all()
    
    return render_template('main/police_dashboard.html',
                         total_evidence=total_evidence,
                         pending_evidence=pending_evidence,
                         analyzed_evidence=analyzed_evidence,
                         recent_evidence=recent_evidence)

@bp.route('/forensic-dashboard')
@login_required
def forensic_dashboard():
    """Forensic analyst dashboard"""
    if not current_user.is_forensic():
        return redirect(url_for('main.dashboard'))
    
    # Get statistics for forensic analysis
    total_evidence = Evidence.query.count()
    pending_analysis = Evidence.query.filter_by(status='submitted').count()
    analyzed_by_me = Evidence.query.filter_by(analyzed_by=current_user.id).count()
    high_priority = Evidence.query.filter_by(priority='high').count()
    
    # Recent evidence for analysis
    recent_evidence = Evidence.query.filter_by(
        status='submitted'
    ).order_by(Evidence.submitted_at.desc()).limit(5).all()
    
    # Evidence assigned to this analyst
    my_evidence = Evidence.query.filter_by(
        analyzed_by=current_user.id
    ).order_by(Evidence.analyzed_at.desc()).limit(5).all()
    
    return render_template('main/forensic_dashboard.html',
                         total_evidence=total_evidence,
                         pending_analysis=pending_analysis,
                         analyzed_by_me=analyzed_by_me,
                         high_priority=high_priority,
                         recent_evidence=recent_evidence,
                         my_evidence=my_evidence)

@bp.route('/profile')
@login_required
def profile():
    """User profile page"""
    return render_template('main/profile.html')