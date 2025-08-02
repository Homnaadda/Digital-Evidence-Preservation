import os
from flask import render_template, request, redirect, url_for, flash, current_app, send_file, jsonify
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from app.evidence import bp
from app.models import Evidence, Case, ChainOfCustody, SystemLog
from app import db
from datetime import datetime

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

@bp.route('/add', methods=['GET', 'POST'])
@login_required
def add_evidence():
    """Add new evidence"""
    if not current_user.is_police():
        flash('Access denied. Only police officers can add evidence.', 'error')
        return redirect(url_for('main.dashboard'))
    
    if request.method == 'POST':
        # Get form data
        case_number = request.form.get('case_number')
        case_title = request.form.get('case_title')
        evidence_title = request.form.get('evidence_title')
        description = request.form.get('description')
        evidence_type = request.form.get('evidence_type')
        priority = request.form.get('priority', 'medium')
        
        # Validate required fields
        if not all([case_number, case_title, evidence_title, evidence_type]):
            flash('Please fill in all required fields.', 'error')
            return render_template('evidence/add_evidence.html')
        
        # Check if case exists, create if not
        case = Case.query.filter_by(case_number=case_number).first()
        if not case:
            case = Case(
                case_number=case_number,
                title=case_title,
                description=f'Case created for evidence: {evidence_title}'
            )
            db.session.add(case)
            db.session.flush()  # Get the case ID
        
        # Generate evidence number
        evidence_count = Evidence.query.count() + 1
        evidence_number = f"EVD-{datetime.now().year}-{evidence_count:06d}"
        
        # Handle file upload
        file_path = None
        file_name = None
        file_size = None
        file_hash = None
        
        if 'evidence_file' in request.files:
            file = request.files['evidence_file']
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                # Create unique filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f"{timestamp}_{filename}"
                
                upload_dir = os.path.join(current_app.instance_path, current_app.config['UPLOAD_FOLDER'])
                file_path = os.path.join(upload_dir, filename)
                
                try:
                    file.save(file_path)
                    file_name = filename
                    file_size = os.path.getsize(file_path)
                    
                    # Calculate file hash
                    import hashlib
                    hash_sha256 = hashlib.sha256()
                    with open(file_path, "rb") as f:
                        for chunk in iter(lambda: f.read(4096), b""):
                            hash_sha256.update(chunk)
                    file_hash = hash_sha256.hexdigest()
                    
                except Exception as e:
                    flash(f'Error uploading file: {str(e)}', 'error')
                    return render_template('evidence/add_evidence.html')
        
        # Create evidence record
        evidence = Evidence(
            evidence_number=evidence_number,
            case_id=case.id,
            title=evidence_title,
            description=description,
            evidence_type=evidence_type,
            priority=priority,
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            file_hash=file_hash,
            submitted_by=current_user.id
        )
        
        db.session.add(evidence)
        db.session.flush()  # Get the evidence ID
        
        # Create chain of custody entry
        custody = ChainOfCustody(
            evidence_id=evidence.id,
            user_id=current_user.id,
            action='submitted',
            notes=f'Evidence submitted by {current_user.full_name}',
            ip_address=request.remote_addr
        )
        db.session.add(custody)
        
        # Log the action
        log_entry = SystemLog(
            user_id=current_user.id,
            action='evidence_submitted',
            resource=f'Evidence {evidence_number}',
            details=f'New evidence submitted: {evidence_title}',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log_entry)
        
        db.session.commit()
        
        flash(f'Evidence {evidence_number} has been successfully submitted!', 'success')
        return redirect(url_for('evidence.view_evidence'))
    
    return render_template('evidence/add_evidence.html')

@bp.route('/view')
@login_required
def view_evidence():
    """View evidence based on user role"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    if current_user.is_admin() or current_user.is_forensic():
        # Admin and forensic can see all evidence
        evidence_query = Evidence.query
    else:
        # Police can only see evidence they submitted
        evidence_query = Evidence.query.filter_by(submitted_by=current_user.id)
    
    # Apply filters
    status_filter = request.args.get('status')
    if status_filter:
        evidence_query = evidence_query.filter_by(status=status_filter)
    
    priority_filter = request.args.get('priority')
    if priority_filter:
        evidence_query = evidence_query.filter_by(priority=priority_filter)
    
    # Paginate results
    evidence_pagination = evidence_query.order_by(
        Evidence.submitted_at.desc()
    ).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    evidence_list = evidence_pagination.items
    
    return render_template('evidence/view_evidence.html',
                         evidence_list=evidence_list,
                         pagination=evidence_pagination)

@bp.route('/detail/<int:evidence_id>')
@login_required
def evidence_detail(evidence_id):
    """View detailed evidence information"""
    evidence = Evidence.query.get_or_404(evidence_id)
    
    # Check permissions
    if not (current_user.is_admin() or 
            current_user.is_forensic() or 
            evidence.submitted_by == current_user.id):
        flash('Access denied.', 'error')
        return redirect(url_for('evidence.view_evidence'))
    
    # Get chain of custody
    custody_chain = ChainOfCustody.query.filter_by(
        evidence_id=evidence_id
    ).order_by(ChainOfCustody.timestamp.desc()).all()
    
    # Log access
    log_entry = SystemLog(
        user_id=current_user.id,
        action='evidence_accessed',
        resource=f'Evidence {evidence.evidence_number}',
        details=f'Evidence details viewed',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(log_entry)
    db.session.commit()
    
    return render_template('evidence/evidence_detail.html',
                         evidence=evidence,
                         custody_chain=custody_chain)

@bp.route('/analyze/<int:evidence_id>', methods=['GET', 'POST'])
@login_required
def analyze_evidence(evidence_id):
    """Analyze evidence (forensic analysts only)"""
    if not current_user.is_forensic():
        flash('Access denied. Only forensic analysts can analyze evidence.', 'error')
        return redirect(url_for('evidence.view_evidence'))
    
    evidence = Evidence.query.get_or_404(evidence_id)
    
    if request.method == 'POST':
        analysis_notes = request.form.get('analysis_notes')
        new_status = request.form.get('status', 'analyzed')
        
        # Update evidence
        evidence.status = new_status
        evidence.analyzed_by = current_user.id
        evidence.analyzed_at = datetime.utcnow()
        
        # Add chain of custody entry
        custody = ChainOfCustody(
            evidence_id=evidence.id,
            user_id=current_user.id,
            action='analyzed',
            notes=analysis_notes,
            ip_address=request.remote_addr
        )
        db.session.add(custody)
        
        # Log the action
        log_entry = SystemLog(
            user_id=current_user.id,
            action='evidence_analyzed',
            resource=f'Evidence {evidence.evidence_number}',
            details=f'Evidence analysis completed',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(log_entry)
        
        db.session.commit()
        
        flash('Evidence analysis has been recorded successfully!', 'success')
        return redirect(url_for('evidence.evidence_detail', evidence_id=evidence_id))
    
    return render_template('evidence/analyze_evidence.html', evidence=evidence)

@bp.route('/download/<int:evidence_id>')
@login_required
def download_evidence(evidence_id):
    """Download evidence file"""
    evidence = Evidence.query.get_or_404(evidence_id)
    
    # Check permissions
    if not (current_user.is_admin() or 
            current_user.is_forensic() or 
            evidence.submitted_by == current_user.id):
        flash('Access denied.', 'error')
        return redirect(url_for('evidence.view_evidence'))
    
    if not evidence.file_path or not os.path.exists(evidence.file_path):
        flash('Evidence file not found.', 'error')
        return redirect(url_for('evidence.evidence_detail', evidence_id=evidence_id))
    
    # Log download
    custody = ChainOfCustody(
        evidence_id=evidence.id,
        user_id=current_user.id,
        action='downloaded',
        notes=f'File downloaded by {current_user.full_name}',
        ip_address=request.remote_addr
    )
    db.session.add(custody)
    
    log_entry = SystemLog(
        user_id=current_user.id,
        action='evidence_downloaded',
        resource=f'Evidence {evidence.evidence_number}',
        details=f'Evidence file downloaded',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(log_entry)
    db.session.commit()
    
    return send_file(evidence.file_path, as_attachment=True, 
                    download_name=evidence.file_name)

@bp.route('/verify-integrity/<int:evidence_id>')
@login_required
def verify_integrity(evidence_id):
    """Verify evidence file integrity"""
    evidence = Evidence.query.get_or_404(evidence_id)
    
    # Check permissions
    if not (current_user.is_admin() or current_user.is_forensic()):
        return jsonify({'error': 'Access denied'}), 403
    
    if not evidence.file_path or not evidence.file_hash:
        return jsonify({'error': 'No file or hash available for verification'}), 400
    
    is_valid = evidence.verify_integrity()
    
    # Log verification
    log_entry = SystemLog(
        user_id=current_user.id,
        action='integrity_check',
        resource=f'Evidence {evidence.evidence_number}',
        details=f'Integrity check result: {"PASSED" if is_valid else "FAILED"}',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )
    db.session.add(log_entry)
    db.session.commit()
    
    return jsonify({
        'valid': is_valid,
        'message': 'File integrity verified' if is_valid else 'File integrity check FAILED'
    })