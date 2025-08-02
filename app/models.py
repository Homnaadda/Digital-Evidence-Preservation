from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
import os
from app import db, login_manager

class User(UserMixin, db.Model):
    """User model for authentication and authorization"""
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='police')  # admin, forensic, police
    full_name = db.Column(db.String(100), nullable=False)
    badge_number = db.Column(db.String(20), unique=True)
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    
    # Relationships
    evidence_submitted = db.relationship('Evidence', backref='submitter', lazy='dynamic',
                                       foreign_keys='Evidence.submitted_by')
    evidence_analyzed = db.relationship('Evidence', backref='analyst', lazy='dynamic',
                                      foreign_keys='Evidence.analyzed_by')
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_forensic(self):
        return self.role == 'forensic'
    
    def is_police(self):
        return self.role == 'police'
    
    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Case(db.Model):
    """Case model for organizing evidence"""
    id = db.Column(db.Integer, primary_key=True)
    case_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default='open')  # open, closed, pending
    priority = db.Column(db.String(10), default='medium')  # low, medium, high, critical
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    evidence_items = db.relationship('Evidence', backref='case', lazy='dynamic')
    
    def __repr__(self):
        return f'<Case {self.case_number}>'

class Evidence(db.Model):
    """Evidence model for digital evidence management"""
    id = db.Column(db.Integer, primary_key=True)
    evidence_number = db.Column(db.String(50), unique=True, nullable=False, index=True)
    case_id = db.Column(db.Integer, db.ForeignKey('case.id'), nullable=False)
    
    # Evidence details
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    evidence_type = db.Column(db.String(50), nullable=False)  # digital, physical, document
    file_path = db.Column(db.String(500))
    file_name = db.Column(db.String(255))
    file_size = db.Column(db.Integer)
    file_hash = db.Column(db.String(64))  # SHA-256 hash for integrity
    
    # Status and workflow
    status = db.Column(db.String(20), default='submitted')  # submitted, analyzing, analyzed, archived
    priority = db.Column(db.String(10), default='medium')
    
    # User relationships
    submitted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    analyzed_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Timestamps
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    analyzed_at = db.Column(db.DateTime)
    
    # Chain of custody
    chain_of_custody = db.relationship('ChainOfCustody', backref='evidence', lazy='dynamic')
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of the file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception:
            return None
    
    def verify_integrity(self):
        """Verify file integrity using stored hash"""
        if not self.file_path or not self.file_hash:
            return False
        current_hash = self.calculate_file_hash(self.file_path)
        return current_hash == self.file_hash
    
    def __repr__(self):
        return f'<Evidence {self.evidence_number}>'

class ChainOfCustody(db.Model):
    """Chain of custody tracking for evidence"""
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.Integer, db.ForeignKey('evidence.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)  # submitted, accessed, analyzed, transferred
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    ip_address = db.Column(db.String(45))  # Support IPv6
    
    # Relationships
    user = db.relationship('User', backref='custody_actions')
    
    def __repr__(self):
        return f'<ChainOfCustody {self.action} by {self.user.username}>'

class SystemLog(db.Model):
    """System activity logging"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    resource = db.Column(db.String(100))
    details = db.Column(db.Text)
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(500))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='system_logs')
    
    def __repr__(self):
        return f'<SystemLog {self.action}>'