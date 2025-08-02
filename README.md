# 🔐 Digital Evidence Management System

A comprehensive digital forensics and evidence management system built with Python Flask, designed for law enforcement agencies to securely manage and track digital evidence throughout the investigation process.

## 📋 Table of Contents
- [Features](#-features)
- [System Architecture](#-system-architecture)
- [Screenshots](#-screenshots)
- [Installation](#-installation)
- [Usage](#-usage)
- [User Roles](#-user-roles)
- [Security Features](#-security-features)
- [Contributing](#-contributing)
- [License](#-license)

## ✨ Features

### 🔍 **Forensic Investigation Management**
- Secure evidence upload and storage
- Digital evidence tracking and chain of custody
- Case management and organization
- Evidence integrity verification

### 👮 **Police Operations**
- Evidence submission and documentation
- Case file management
- Evidence viewing and analysis
- Real-time status tracking

### 👨‍💼 **Administrative Control**
- User management (add/delete users)
- System monitoring and logs
- Access control and permissions
- Audit trail maintenance

### 🔒 **Security & Compliance**
- Role-based access control
- Secure authentication system
- Data encryption and protection
- Comprehensive logging system

## 🏗️ System Architecture

The system is built using:
- **Backend**: Python Flask framework
- **Database**: SQLite/PostgreSQL for data storage
- **Frontend**: HTML, CSS, JavaScript
- **Security**: Session management, role-based authentication
- **File Storage**: Secure evidence file handling

## 📸 Screenshots

### 🔐 Login System
![Login Page](Images/Login%20Page.png)
*Secure authentication system with role-based access*

### 🏠 Forensic Dashboard
![Forensic Home](Images/Forensic-Home%20page.png)
*Main dashboard for forensic investigators*

### 📁 Evidence Management
![Police Add Evidence](Images/Police-Add%20Evidence.png)
*Police interface for adding new evidence*

![Police View Evidence](Images/Police-View%20Evidence.png)
*Evidence viewing and management interface*

![Forensic View Evidence](Images/Forensic-View%20Evidence.png)
*Forensic analyst evidence review interface*

### 👨‍💼 Administrative Features
![Admin User Management](Images/Admin-Add%20&%20Delete%20User.png)
*Administrative user management interface*

![System Logs](Images/Admin-System%20Logs.png)
*Comprehensive system logging and monitoring*

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Virtual environment (recommended)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd digital-evidence-management
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Initialize the database**
   ```bash
   python vault.py
   ```

5. **Run the application**
   ```bash
   python vault.py
   ```

6. **Access the system**
   - Open your browser and navigate to `http://localhost:5000`
   - Use the default admin credentials to log in

## 💻 Usage

### 🔑 First Time Setup
1. Start the application using `python vault.py`
2. Navigate to the login page
3. Log in with administrator credentials
4. Create user accounts for police officers and forensic analysts
5. Begin managing digital evidence

### 📝 Adding Evidence
1. Log in as a police officer
2. Navigate to "Add Evidence" section
3. Fill in case details and upload evidence files
4. Submit for forensic analysis

### 🔍 Forensic Analysis
1. Log in as a forensic analyst
2. View assigned evidence cases
3. Analyze and document findings
4. Update case status and reports

## 👥 User Roles

### 🚔 **Police Officer**
- ➕ Add new evidence to cases
- 👀 View evidence they've submitted
- 📊 Track case progress
- 📝 Update case information

### 🔬 **Forensic Analyst**
- 🔍 Access all evidence for analysis
- 📋 Generate forensic reports
- ✅ Verify evidence integrity
- 📈 Update analysis status

### 👨‍💼 **Administrator**
- 👤 Manage user accounts
- 📊 Monitor system activity
- 🔧 Configure system settings
- 📋 Access comprehensive logs

## 🔐 Security Features

- 🔒 **Secure Authentication**: Role-based login system
- 🛡️ **Data Protection**: Encrypted evidence storage
- 📝 **Audit Trail**: Comprehensive logging of all activities
- 🔑 **Access Control**: Granular permissions based on user roles
- 🔐 **Session Management**: Secure session handling
- 📊 **System Monitoring**: Real-time activity tracking

## 🛠️ Technical Details

### File Structure
```
digital-evidence-management/
├── vault.py              # Main application file
├── Images/               # Screenshot documentation
├── templates/            # HTML templates
├── static/              # CSS, JS, and static assets
├── database/            # Database files
└── uploads/             # Evidence file storage
```

### Key Components
- **Authentication System**: Secure login with role validation
- **Evidence Handler**: File upload and storage management
- **Database Manager**: SQLite/PostgreSQL integration
- **Logging System**: Comprehensive activity tracking
- **User Interface**: Responsive web-based interface

## 🤝 Contributing

We welcome contributions to improve the Digital Evidence Management System!

1. 🍴 Fork the repository
2. 🌿 Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. 💾 Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. 📤 Push to the branch (`git push origin feature/AmazingFeature`)
5. 🔄 Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For support and questions:
- 📧 Email: support@evidence-management.com
- 📋 Issues: Create an issue on GitHub
- 📖 Documentation: Check the wiki for detailed guides

## 🙏 Acknowledgments

- Built for law enforcement and forensic professionals
- Designed with security and compliance in mind
- Developed following digital forensics best practices

---

**⚠️ Important Security Notice**: This system handles sensitive law enforcement data. Ensure proper security measures are in place before deployment in production environments.

**🔒 Data Protection**: All evidence files and case information are handled according to digital forensics standards and chain of custody requirements.