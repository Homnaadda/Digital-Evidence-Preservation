// Main JavaScript for Digital Evidence Management System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // File upload handling
    const fileInput = document.getElementById('evidence_file');
    const fileUploadArea = document.querySelector('.file-upload-area');
    
    if (fileInput && fileUploadArea) {
        // Click to upload
        fileUploadArea.addEventListener('click', function() {
            fileInput.click();
        });

        // Drag and drop
        fileUploadArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            fileUploadArea.classList.add('dragover');
        });

        fileUploadArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            fileUploadArea.classList.remove('dragover');
        });

        fileUploadArea.addEventListener('drop', function(e) {
            e.preventDefault();
            fileUploadArea.classList.remove('dragover');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                fileInput.files = files;
                updateFileDisplay(files[0]);
            }
        });

        // File input change
        fileInput.addEventListener('change', function(e) {
            if (e.target.files.length > 0) {
                updateFileDisplay(e.target.files[0]);
            }
        });
    }

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    // Confirm delete actions
    const deleteButtons = document.querySelectorAll('[data-confirm-delete]');
    deleteButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const message = button.getAttribute('data-confirm-delete') || 'Are you sure you want to delete this item?';
            
            if (confirm(message)) {
                // If it's a form submission
                const form = button.closest('form');
                if (form) {
                    form.submit();
                } else {
                    // If it's an AJAX call
                    const url = button.getAttribute('href') || button.getAttribute('data-url');
                    if (url) {
                        performDeleteAction(url, button);
                    }
                }
            }
        });
    });

    // Evidence integrity check
    const integrityButtons = document.querySelectorAll('.check-integrity');
    integrityButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            const evidenceId = button.getAttribute('data-evidence-id');
            checkEvidenceIntegrity(evidenceId, button);
        });
    });

    // Search functionality
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        let searchTimeout;
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(function() {
                performSearch(searchInput.value);
            }, 300);
        });
    }

    // Auto-refresh for real-time updates (every 30 seconds)
    if (document.querySelector('[data-auto-refresh]')) {
        setInterval(function() {
            refreshPageData();
        }, 30000);
    }
});

// Update file display in upload area
function updateFileDisplay(file) {
    const fileUploadArea = document.querySelector('.file-upload-area');
    const fileInfo = document.querySelector('.file-info');
    
    if (fileUploadArea && file) {
        const fileSize = formatFileSize(file.size);
        const fileName = file.name;
        
        fileUploadArea.innerHTML = `
            <div class="file-selected">
                <i class="fas fa-file fa-3x text-success mb-3"></i>
                <h5>${fileName}</h5>
                <p class="text-muted">Size: ${fileSize}</p>
                <small class="text-success">
                    <i class="fas fa-check-circle me-1"></i>
                    File selected successfully
                </small>
            </div>
        `;
    }
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Perform delete action via AJAX
function performDeleteAction(url, button) {
    showSpinner();
    
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': getCSRFToken()
        }
    })
    .then(response => response.json())
    .then(data => {
        hideSpinner();
        
        if (data.success) {
            showAlert('success', data.success);
            // Remove the row or refresh the page
            const row = button.closest('tr');
            if (row) {
                row.remove();
            } else {
                setTimeout(() => location.reload(), 1000);
            }
        } else {
            showAlert('error', data.error || 'An error occurred');
        }
    })
    .catch(error => {
        hideSpinner();
        showAlert('error', 'Network error occurred');
        console.error('Error:', error);
    });
}

// Check evidence integrity
function checkEvidenceIntegrity(evidenceId, button) {
    const originalText = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin me-1"></i>Checking...';
    button.disabled = true;
    
    fetch(`/evidence/verify-integrity/${evidenceId}`)
    .then(response => response.json())
    .then(data => {
        button.innerHTML = originalText;
        button.disabled = false;
        
        if (data.valid) {
            showAlert('success', data.message);
            button.classList.remove('btn-warning');
            button.classList.add('btn-success');
            button.innerHTML = '<i class="fas fa-check me-1"></i>Verified';
        } else {
            showAlert('error', data.message);
            button.classList.remove('btn-warning');
            button.classList.add('btn-danger');
            button.innerHTML = '<i class="fas fa-exclamation-triangle me-1"></i>Failed';
        }
    })
    .catch(error => {
        button.innerHTML = originalText;
        button.disabled = false;
        showAlert('error', 'Error checking integrity');
        console.error('Error:', error);
    });
}

// Show alert message
function showAlert(type, message) {
    const alertContainer = document.querySelector('.container');
    const alertClass = type === 'error' ? 'danger' : type;
    const iconClass = type === 'success' ? 'check-circle' : 
                     type === 'error' ? 'exclamation-triangle' : 'info-circle';
    
    const alertHTML = `
        <div class="alert alert-${alertClass} alert-dismissible fade show" role="alert">
            <i class="fas fa-${iconClass} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    alertContainer.insertAdjacentHTML('afterbegin', alertHTML);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        const alert = alertContainer.querySelector('.alert');
        if (alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }
    }, 5000);
}

// Show loading spinner
function showSpinner() {
    const spinnerHTML = `
        <div class="spinner-overlay">
            <div class="spinner-border-custom"></div>
        </div>
    `;
    document.body.insertAdjacentHTML('beforeend', spinnerHTML);
}

// Hide loading spinner
function hideSpinner() {
    const spinner = document.querySelector('.spinner-overlay');
    if (spinner) {
        spinner.remove();
    }
}

// Get CSRF token
function getCSRFToken() {
    const token = document.querySelector('meta[name="csrf-token"]');
    return token ? token.getAttribute('content') : '';
}

// Perform search
function performSearch(query) {
    if (query.length < 2) return;
    
    // Implementation depends on the specific page
    console.log('Searching for:', query);
}

// Refresh page data
function refreshPageData() {
    // Implementation for real-time updates
    console.log('Refreshing page data...');
}

// Export functions for use in other scripts
window.EvidenceVault = {
    showAlert,
    showSpinner,
    hideSpinner,
    formatFileSize,
    checkEvidenceIntegrity
};