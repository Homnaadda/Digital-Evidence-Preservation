import os
import subprocess
import tempfile
import logging
import atexit
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import sqlite3
import hashlib
import shutil
from datetime import datetime
import platform
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

ENCRYPTION_KEY = Fernet.generate_key()

global current_user_id
current_user_id = None

logging.basicConfig(level=logging.DEBUG, filename='app.log', filemode='w',
                    format='%(name)s - %(levelname)s - %(message)s')


# Function to create the database and users table
def create_database():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT UNIQUE,
            password TEXT,
            user_type TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS uploads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT UNIQUE,
            case_name TEXT,
            file_path TEXT,
            file_hash TEXT,
            uploaded_by TEXT,
            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    c.execute('''
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id TEXT,
        user_type TEXT,
        action TEXT
        )
    ''')
    
    # Insert default user if not exists
    user_id = "PD104"
    password = "password"
    user_type = "Admin"
    
    c.execute('SELECT * FROM users WHERE user_id=?', (user_id,))
    if not c.fetchone():  # Check if user already exists
        c.execute('INSERT INTO users (user_id, password, user_type) VALUES (?, ?, ?)', (user_id, password, user_type))
    
    conn.commit()
    conn.close()

def verify_database_structure():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Check if uploads table exists
    c.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='uploads';
    """)
    
    if not c.fetchone():
        # Create uploads table if it doesn't exist
        c.execute('''
            CREATE TABLE uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_number TEXT UNIQUE,
                case_name TEXT,
                file_path TEXT,
                file_hash TEXT,
                uploaded_by TEXT,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
    
    conn.close()

def show_login():
    for widget in root.winfo_children():
        widget.destroy()
    create_login_frame()

def login():
    global current_user_id
    user_id = id_entry.get()
    password = password_entry.get()
    user_type = user_type_entry.get()
    
    if user_type == "Select User Type":
        messagebox.showerror("Login Failed", "Please select a user type.")
        return
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE user_id=? AND password=? AND user_type=?', (user_id, password, user_type))
    user = c.fetchone()

    if user:
        current_user_id = user[1]  # Set the current_user_id
        # Log the login activity
        c.execute('INSERT INTO activity_logs (user_id, user_type, action) VALUES (?, ?, ?)',
                  (user_id, user_type, "Login"))
        conn.commit()

        if user[3] == "Police Department":
            show_welcome(user[3])  # Pass user type to the welcome function
        elif user[3] == "Admin":
            show_admin_dashboard()  # Show admin dashboard
        elif user[3] == "Forensic Investigator":
            show_forensic_investigator_dashboard()
        else:
            messagebox.showinfo("Login Successful", f"Welcome, {user_type} user. This portal is currently only available for Police Department.")
    else:
        messagebox.showerror("Login Failed", "Invalid ID, Password, or User Type.")
    
    conn.close()

def show_admin_dashboard():
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#FF6F61", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0)
    home_button.pack(side=tk.LEFT, padx=10)

    manage_user_button = tk.Button(nav_frame, text="Manage Users", bg="white", fg="#FF6F61", borderwidth=0, command=show_manage_users)
    manage_user_button.pack(side=tk.LEFT, padx=10)

    logs_button = tk.Button(nav_frame, text="Logs", bg="white", fg="#FF6F61", borderwidth=0, command=show_logs)
    logs_button.pack(side=tk.LEFT, padx=10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=show_login)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Admin Dashboard Content
    admin_content_frame = tk.Frame(root, bg="#f0f0f0")
    admin_content_frame.pack(expand=True, fill=tk .BOTH)

def show_logs():
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#FF6F61", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0, command=show_admin_dashboard)
    home_button.pack(side=tk.LEFT, padx=10)

    manage_user_button = tk.Button(nav_frame, text="Manage Users", bg="white", fg="#FF6F61", borderwidth=0, command=show_manage_users)
    manage_user_button.pack(side=tk.LEFT, padx=10)

    logs_button = tk.Button(nav_frame, text="Logs", bg="white", fg="#FF6F61", borderwidth=0)
    logs_button.pack(side=tk.LEFT, padx=10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=show_login)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Logs Content
    logs_frame = tk.Frame(root, bg="#f0f0f0")
    logs_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

    logs_title = tk.Label(logs_frame, text="System Logs", font=("Arial", 18, "bold"), fg="#333", bg="#f0f0f0")
    logs_title.pack(pady=(0, 10))

    # Create a text widget to display logs
    logs_text = tk.Text(logs_frame, wrap=tk.WORD, width=80, height=20)
    logs_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    # Add a scrollbar
    scrollbar = tk.Scrollbar(logs_frame, command=logs_text.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    logs_text.config(yscrollcommand=scrollbar.set)

    # Fetch and display logs
    display_logs(logs_text)

def display_logs(logs_text):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    try:
        # Fetch logs from both uploads and activity_logs tables
        c.execute('''
            SELECT 'Evidence' as log_type, case_number, case_name, uploaded_by, upload_date as timestamp
            FROM uploads
            UNION ALL
            SELECT 'Activity' as log_type, user_id, user_type, action, timestamp
            FROM activity_logs
            ORDER BY timestamp DESC
        ''')
        logs = c.fetchall()

        if logs:
            for log in logs:
                log_type, id_or_case, name_or_type, action_or_uploader, timestamp = log
                try:
                    # Try parsing with microseconds
                    timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    try:
                        # Try parsing without microseconds
                        timestamp = datetime.strptime(timestamp, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        # If both fail, use current timestamp
                        timestamp = datetime.now()
                
                formatted_timestamp = timestamp.strftime('%d-%m-%Y %H:%M')
                
                if log_type == 'Evidence':
                    log_entry = f"{formatted_timestamp} Case Number: {id_or_case} Case Name: {name_or_type} Uploaded By: {action_or_uploader}\n"
                else:  # Activity
                    log_entry = f"{formatted_timestamp} User ID: {id_or_case} User Type: {name_or_type} Action: {action_or_uploader}\n"
                
                logs_text.insert(tk.END, log_entry)
        else:
            logs_text.insert(tk.END, "No logs available.")

    except sqlite3.Error as e:
        logs_text.insert(tk.END, f"An error occurred while fetching logs: {str(e)}")

    finally:
        conn.close()

    # Make the text widget read-only
    logs_text.config(state=tk.DISABLED) 

def show_manage_users():
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#FF6F61", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0)
    home_button.pack(side=tk.LEFT, padx=10)

    manage_user_button = tk.Button(nav_frame, text="Manage Users", bg="white", fg="#FF6F61", borderwidth=0)
    manage_user_button.pack(side=tk.LEFT, padx=10)

    logs_button = tk.Button(nav_frame, text="Logs", bg="white", fg="#FF6F61", borderwidth=0,command=show_logs)
    logs_button.pack(side=tk.LEFT, padx=10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=show_login)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Manage Users Form
    manage_users_frame = tk.Frame(root, bg="#f0f0f0")
    manage_users_frame.pack(pady=50)

    operation_label = tk.Label(manage_users_frame, text="Operation", bg="#f0f0f0", fg="#333")
    operation_label.pack()

    operation_entry = ttk.Combobox(manage_users_frame, values=["Add User", "Delete User"])
    operation_entry.pack()

    id_label = tk.Label(manage_users_frame, text="ID", bg="#f0f0f0", fg="#333")
    id_label.pack()

    id_entry = tk.Entry(manage_users_frame, width=30)
    id_entry.pack()

    password_label = tk.Label(manage_users_frame, text="Password", bg="#f0f0f0", fg="#333")
    password_label.pack()

    password_entry = tk.Entry(manage_users_frame, width=30, show="*")
    password_entry.pack()

    organization_label = tk.Label(manage_users_frame, text="Organization", bg="#f0f0f0", fg="#333")
    organization_label.pack()

    organization_entry = ttk.Combobox(manage_users_frame, values=["Select Organization", "Police Department", "Forensic Investigator"])
    organization_entry.pack()

    submit_button = tk.Button(manage_users_frame, text="Submit", bg="#FF6F61", fg="white", command=lambda: manage_users(operation_entry.get(), id_entry.get(), password_entry.get(), organization_entry.get()))
    submit_button.pack(pady=20)

def manage_users(operation, user_id, password, organization):
    if not all([operation, user_id, password, organization]):
        messagebox.showerror("Error", "Please fill in all fields")
        return
        
    if organization == "Select Organization":
        messagebox.showerror("Error", "Please select an organization")
        return
        
    # Check if organization is valid
    valid_organizations = ["Police Department", "Forensic Investigator"]
    if organization not in valid_organizations:
        messagebox.showerror("Error", "Invalid organization type. Only Police Department and Forensic Investigator are allowed.")
        return

    conn = sqlite3.connect('users.db')
    c = conn.cursor()

    try:
        if operation == "Add User":
            # Check if user already exists
            c.execute('SELECT * FROM users WHERE user_id=?', (user_id,))
            if c.fetchone():
                messagebox.showerror("Error", "User ID already exists")
                return
            
            # Add new user
            c.execute('INSERT INTO users (user_id, password, user_type) VALUES (?, ?, ?)',
                     (user_id, password, organization))
            conn.commit()
            messagebox.showinfo("Success", f"User {user_id} added successfully")

        elif operation == "Delete User":
            # Check if user exists
            c.execute('SELECT * FROM users WHERE user_id=?', (user_id,))
            if not c.fetchone():
                messagebox.showerror("Error", "User ID does not exist")
                return
            
            # Don't allow deletion of admin users
            c.execute('SELECT user_type FROM users WHERE user_id=?', (user_id,))
            user_type = c.fetchone()[0]
            if user_type == "Admin":
                messagebox.showerror("Error", "Cannot delete admin users")
                return
            
            # Delete user
            c.execute('DELETE FROM users WHERE user_id=?', (user_id,))
            conn.commit()
            messagebox.showinfo("Success", f"User {user_id} deleted successfully")

        else:
            messagebox.showerror("Error", "Invalid operation")

    except sqlite3.Error as e:
        messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
    
    finally:
        conn.close()

def show_welcome(user_type):
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#FF5A5F", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0)
    home_button.pack(side=tk.LEFT, padx=10)

    upload_button = tk.Button(nav_frame, text="Upload", bg="white", fg="#FF5A5F", borderwidth=0, command=show_upload_page)
    upload_button.pack(side=tk.LEFT, padx=10)

    view_button = tk.Button(nav_frame, text="View", bg="white", fg="#FF5A5F", borderwidth=0, command=show_view_page)
    view_button.pack(side=tk.LEFT, padx =10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=show_login)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Profile section
    profile_frame = tk.Frame(root, bg="#f0f0f0")
    profile_frame.pack(pady=50)

    # You need to replace 'path_to_your_image.png' with an actual image path
    profile_image = tk.Label(profile_frame, bg="#f0f0f0")
    profile_image_img = tk.PhotoImage(file="path_to_your_image.png")  # Add your image path here
    profile_image.config(image=profile_image_img)
    profile_image.image = profile_image_img  # Keep a reference
    profile_image.pack()

    welcome_label = tk.Label(root, text=f"Welcome Back {user_type}", font=("Arial", 32), fg="#333", bg="#f0f0f0")
    welcome_label.pack(pady=20)

def create_login_frame():
    global id_entry, password_entry, user_type_entry
    
    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#FF5A5F", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0)
    home_button.pack(side=tk.LEFT, padx=10)

    login_button = tk.Button(nav_frame, text="Login", bg="white", fg="#FF5A5F", borderwidth=0, command=login)
    login_button.pack(side=tk.LEFT, padx=10)

    contact_button = tk.Button(nav_frame, text="Contact", bg="white", fg="#666", borderwidth=0)
    contact_button.pack(side=tk.LEFT, padx=10)

    # Login Container
    login_frame = tk.Frame(root, bg="#f0f0f0")
    login_frame.pack(expand=True)

    login_box = tk.Frame(login_frame, bg="white", padx=40, pady=40)
    login_box.pack()

    login_title = tk.Label(login_box, text="Login", font=("Arial", 20, "bold"), fg="#FF5A5F", bg="white")
    login_title.pack()

    id_label = tk.Label(login_box, text="User ID", bg="white", fg="#666")
    id_label.pack(anchor=tk.W)
    id_entry = tk.Entry(login_box, width=30)
    id_entry.pack(pady=5)

    password_label = tk.Label(login_box, text="Password", bg="white", fg="#666")
    password_label.pack(anchor=tk.W)
    password_entry = tk.Entry(login_box, width=30, show="*")
    password_entry.pack(pady=5)

    user_type_label = tk.Label(login_box, text="User Type", bg="white", fg="#666")
    user_type_label.pack(anchor=tk.W)
    user_type_entry = ttk.Combobox(login_box, values=["Select User Type", "Admin", "Police Department", "Forensic Investigator"], width=28)
    user_type_entry.current(0)
    user_type_entry.pack(pady=5)

    login_btn = tk.Button(login_box, text="Login", bg="#FF5A5F", fg="white", width=30, command=login)
    login_btn.pack(pady=20)

def show_upload_page():
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#FF5A5F", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0, command=lambda: show_welcome("Police Department"))
    home_button.pack(side=tk.LEFT, padx=10)

    upload_button = tk.Button(nav_frame, text="Upload", bg="white", fg="#FF5A5F", borderwidth=0)
    upload_button.pack(side=tk.LEFT, padx=10)

    view_button = tk.Button(nav_frame, text="View", bg="white", fg="#FF5A5F", borderwidth=0, command=show_view_page)
    view_button.pack(side=tk.LEFT, padx=10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=show_login)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Upload Container
    upload_frame = tk.Frame(root, bg="#f0f0f0")
    upload_frame.pack(expand=True, fill=tk.BOTH)

    upload_box = tk.Frame(upload_frame, bg="white", padx=40, pady=40)
    upload_box.pack(expand=True, pady=50)

    upload_title = tk.Label(upload_box, text="Upload Evidence", font=("Arial", 20, "bold"), fg="#FF5A5F", bg="white")
    upload_title.pack(pady=(0, 20))

    # Create a container for the form
    form_frame = tk.Frame(upload_box, bg="white")
    form_frame.pack(fill=tk.BOTH, expand=True)

    # Variables to store input values
    case_number_var = tk.StringVar()
    case_name_var = tk.StringVar()
    selected_file_path = tk.StringVar()

    # Case Number
    case_number_label = tk.Label(form_frame, text="Case Number *", bg="white", fg="#666", font=("Arial", 10, "bold"))
    case_number_label.pack(anchor=tk.W, pady=(0, 5))
    case_number_entry = tk.Entry(form_frame, width=40, textvariable=case_number_var)
    case_number_entry.pack(anchor=tk.W, pady=(0, 15))

    # Case Name
    case_name_label = tk.Label(form_frame, text="Case Name *", bg="white", fg="#666", font=("Arial", 10, "bold"))
    case_name_label.pack(anchor=tk.W, pady=(0, 5))
    case_name_entry = tk.Entry(form_frame, width=40, textvariable=case_name_var)
    case_name_entry.pack(anchor=tk.W, pady=(0, 15))

    # File Selection
    file_label = tk.Label(form_frame, text="Select Evidence File *", bg="white", fg="#666", font=("Arial", 10, "bold"))
    file_label.pack(anchor=tk.W, pady=(0, 5))
    
    file_frame = tk.Frame(form_frame, bg="white")
    file_frame.pack(fill=tk.X, pady=(0, 15))
    
    file_path_label = tk.Label(file_frame, text="No file selected", bg="white", fg="#666")
    file_path_label.pack(side=tk.LEFT)

    def choose_file():
        try:
            file_path = filedialog.askopenfilename(
                title="Select Evidence File",
                filetypes=[
                    ("All Files", "*.*"),
                    ("PDF Files", "*.pdf"),
                    ("Image Files", "*.png *.jpg *.jpeg"),
                    ("Document Files", "*.doc *.docx")
                ]
            )
            if file_path:
                selected_file_path.set(file_path)
                file_path_label.config(text=os.path.basename(file_path))
                print(f"Selected file: {file_path}")  # Debug print
        except Exception as e:
            print(f"Error selecting file: {str(e)}")
            messagebox.showerror("Error", f"Error selecting file: {str(e)}")

    def upload_file():
        global current_user_id
        try:
            # Get the input values
            case_number = case_number_var.get().strip()
            case_name = case_name_var.get().strip()
            file_path = selected_file_path.get()

            # Validate inputs
            if not all([case_number, case_name, file_path]):
                messagebox.showerror("Error", "Please fill in all required fields and select a file")
                return
            if current_user_id is None:
                messagebox.showerror("Error", "No user is currently logged in. Please log in and try again.")
                return

            print(f"Uploading file: {file_path}")  # Debug print
            print(f"Case Number: {case_number}")    # Debug print
            print(f"Case Name: {case_name}")        # Debug print

            # Create secure directory if it doesn't exist
            secure_dir = get_secure_directory()
            print(f"Secure directory: {secure_dir}")  # Debug print

            # Generate secure path for the file
            secure_path = secure_file_copy(file_path, case_number)
            print(f"Secure path: {secure_path}")  # Debug print

            # Calculate file hash
            file_hash = calculate_file_hash(file_path)
            print(f"File hash: {file_hash}")  # Debug print

            # Store in database
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            
            # Get current timestamp
            current_time = datetime.now()
            
            c.execute('''
                INSERT INTO uploads 
                (case_number, case_name, file_path, file_hash, uploaded_by, upload_date) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (case_number, case_name, secure_path, file_hash, current_user_id, current_time))
            
            conn.commit()
            conn.close()

            # Clear the form
            case_number_var.set("")
            case_name_var.set("")
            selected_file_path.set("")
            file_path_label.config(text="No file selected")

            messagebox.showinfo("Success", "Evidence file uploaded successfully!")

        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e):
                messagebox.showerror("Error", "A case with this number already exists.")
            else:
                messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
        except Exception as e:
            print(f"Upload error: {str(e)}")  # Debug print
            messagebox.showerror("Error", f"Failed to upload file: {str(e)}")

    # File selection button
    choose_file_btn = tk.Button(
        form_frame,
        text="Choose File",
        command=choose_file,
        bg="#FF5A5F",
        fg="white",
        font=("Arial",  10, "bold")
    )
    choose_file_btn.pack(anchor=tk.W, pady=(0, 15))

    # Upload button
    upload_btn = tk.Button(
        upload_box,
        text="Upload Evidence",
        command=upload_file,
        bg="#FF5A5F",
        fg="white",
        font=("Arial", 12, "bold")
    )
    upload_btn.pack(pady=(20, 0))

    # Back button
    back_btn = tk.Button(
        upload_box,
        text="Back",
        command=lambda: show_welcome("Police Department"),
        bg="white",
        fg="#666",
        borderwidth=0
    )
    back_btn.pack(pady=(10, 0))

# Ensure to call show_upload_page() when you want to display the upload interface.
    # Add status label
    status_label = tk.Label(upload_box, text="", bg="white", fg="#666")
    status_label.pack(pady=10)

def show_view_page():
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#FF5A5F", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0)
    home_button.pack(side=tk.LEFT, padx=10)

    upload_button = tk.Button(nav_frame, text="Upload", bg="white", fg="#FF5A5F", borderwidth=0, command=show_upload_page)
    upload_button.pack(side=tk.LEFT, padx=10)

    view_button = tk.Button(nav_frame, text="View", bg="white", fg="#FF5A5F", borderwidth=0, command=show_view_page)
    view_button.pack(side=tk.LEFT, padx=10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=show_login)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Search Container
    search_frame = tk.Frame(root, bg="#f5f5f5")
    search_frame.pack(pady=20)

    search_box = tk.Frame(search_frame, bg="white", relief="solid", borderwidth=1)
    search_box.pack(padx=20, pady=10)

    # Search Entry with placeholder
    search_entry = tk.Entry(search_box, width=40, font=("Arial", 12))
    search_entry.insert(0, "Search Case number")
    search_entry.config(fg='grey')
    search_entry.pack(side=tk.LEFT, padx=10, pady=10)

    def on_entry_click(event):
        if search_entry.get() == "Search Case number":
            search_entry.delete(0, tk.END)
            search_entry.config(fg='black')

    def on_focusout(event):
        if search_entry.get() == "":
            search_entry.insert(0, "Search Case number")
            search_entry.config(fg='grey')

    search_entry.bind('<FocusIn>', on_entry_click)
    search_entry.bind('<FocusOut>', on_focusout)

    # Search Button with functionality
    search_button = tk.Button(search_box, text="🔍", bg="white", fg="#666", 
                             borderwidth=0, font=("Arial", 12), command=lambda: search_case(search_entry.get()))
    search_button.pack(side=tk.LEFT, padx=(0, 10))

    # Results Frame with better styling
    results_frame = tk.Frame(root, bg="#f5f5f5")
    results_frame.pack(pady=20, fill=tk.BOTH, expand=True, padx=40)  # Added padding

    # Create a separate frame for headings
    headings_frame = tk.Frame(results_frame, bg="#f5f5f5")
    headings_frame.pack(fill=tk.X, pady=(0, 10))

    # Configure columns to be evenly spaced
    for i in range(5):
        headings_frame.grid_columnconfigure(i, weight=1)

    # Headings with improved styling
    headings = ["Uploaded Date", "Uploaded Time", "Case Number", "Case Name", "Link"]
    for i, heading in enumerate(headings):
        heading_label = tk.Label(
            headings_frame, 
            text=heading, 
            font=("Arial", 12, "bold"),
            bg="#e6e6e6",  # Slightly darker background for headers
            fg="#333",
            pady=10,  # Vertical padding
            padx=15,  # Horizontal padding
            relief="raised",  # Gives a raised effect
            borderwidth=1
        )
        heading_label.grid(
            row=0, 
            column=i, 
            padx=5,  # Space between columns
            sticky="nsew"  # Stretch in all directions
        )

    # Add a separator line
    separator = tk.Frame(results_frame, height=2, bg="#cccccc")
    separator.pack(fill=tk.X, pady=(0, 10))

    # Create a frame for search results
    global search_results_frame
    search_results_frame = tk.Frame(results_frame, bg="#f5f5f5")
    search_results_frame.pack(fill=tk.BOTH, expand=True)

def search_case(case_number):
    print(f"Searching for case number: {case_number}")

    # Clear previous results
    for widget in search_results_frame.winfo_children():
        widget.destroy()

    if not case_number or case_number == "Search Case number":
        print("No case number entered")
        return

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        query = 'SELECT upload_date, case_number, case_name, file_path FROM uploads WHERE case_number=?'
        c.execute(query, (case_number,))
        results = c.fetchall()

        # Configure columns in search_results_frame
        for i in range(5):
            search_results_frame.grid_columnconfigure(i, weight=1)
        
        if results:
            for i, (upload_date, case_number, case_name, file_path) in enumerate(results, start=1):
                try:
                    date_obj = datetime.strptime(upload_date, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    date_obj = datetime.strptime(upload_date, '%Y-%m-%d %H:%M:%S')
                uploaded_date = date_obj.strftime('%Y-%m-%d')
                uploaded_time = date_obj.strftime('%H:%M:%S')
                
                # Create result labels with consistent styling
                tk.Label(
                    search_results_frame, 
                    text=uploaded_date, 
                    bg="#f5f5f5",
                    padx=15,
                    pady=8
                ).grid(row=i, column=0, sticky="nsew")
                
                tk.Label(
                    search_results_frame, 
                    text=uploaded_time, 
                    bg="#f5f5f5",
                    padx=15,
                    pady=8
                ).grid(row=i, column=1, sticky="nsew")
                
                tk.Label(
                    search_results_frame, 
                    text=case_number, 
                    bg="#f5f5f5",
                    padx=15,
                    pady=8
                ).grid(row=i, column=2, sticky="nsew")
                
                tk.Label(
                    search_results_frame, 
                    text=case_name, 
                    bg="#f5f5f5",
                    padx=15,
                    pady=8
                ).grid(row=i, column=3, sticky="nsew")
                
                view_button = tk.Button(
                    search_results_frame, 
                    text="View",
                    command=lambda fp=file_path: open_file(fp),
                    bg="#FF5A5F",
                    fg="white",
                    padx=15,
                    pady=5
                )
                view_button.grid(row=i, column=4, padx=5, pady=5, sticky="nsew")

                delete_button = tk.Button(
                    search_results_frame, 
                    text="Delete",
                    command=lambda case_num=case_number, file_path=file_path: delete_file(case_num, file_path),
                    bg="red",
                    fg="white",
                    padx=15,
                    pady=5
                )
                delete_button.grid(row=i, column=5, padx=5, pady=5, sticky="nsew")
        else:
            no_results_label = tk.Label(
                search_results_frame, 
                text="No Matches Found", 
                fg="red", 
                bg="#f5f5f5",
                font=("Arial", 12),
                pady=20
            )
            no_results_label.grid(row=1, column=0, columnspan=6, sticky="nsew")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
    finally:
        if conn:
            conn.close()

def delete_file(case_number, file_path):
    # Confirm deletion
    if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the case '{case_number}'? This action cannot be undone."):
        try:
            # Delete from database
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('DELETE FROM uploads WHERE case_number = ?', (case_number,))
            conn.commit()
            conn.close()

            # Delete file from file system
            if os.path.exists(file_path):
                os.remove(file_path)
            
            messagebox.showinfo("Success", f"Case '{case_number}' has been deleted successfully.")
            
            # Refresh the search results
            search_case(case_number)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while deleting the file: {str(e)}")
            logging.error(f"Error deleting file: {str(e)}")
    

def open_file(encrypted_file_path):
    if not os.path.exists(encrypted_file_path):
        error_msg = f"File not found: {encrypted_file_path}"
        logging.error(error_msg)
        messagebox.showerror("Error", error_msg)
        return

    try:
        original_extension = os.path.splitext(os.path.splitext(encrypted_file_path)[0])[1]
        logging.debug(f"Original extension: {original_extension}")
        
        temp_fd, temp_path = tempfile.mkstemp(suffix=original_extension)
        logging.debug(f"Temporary file created: {temp_path}")
        
        try:
            decrypted_data = decrypt_file(encrypted_file_path, ENCRYPTION_KEY)
            logging.debug(f"File decrypted successfully")
            
            with os.fdopen(temp_fd, 'wb') as temp_file:
                temp_file.write(decrypted_data)
            logging.debug(f"Decrypted data written to temporary file")

            if platform.system() == "Windows":
                os.startfile(temp_path)
            elif platform.system() == "Darwin":  # macOS
                subprocess.run(["open", temp_path])
            else:  # Linux
                subprocess.run(["xdg-open", temp_path])
            logging.debug(f"File opened with system default application")
            
            # Instead of deleting after 30 seconds, we'll delete when the application closes
            atexit.register(lambda: os.unlink(temp_path) if os.path.exists(temp_path) else None)
            
        except Exception as e:
            os.close(temp_fd)
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise e
            
    except Exception as e:
        error_msg = f"Failed to open file: {str(e)}"
        logging.error(error_msg)
        messagebox.showerror("Error", error_msg)
        print(f"Error details: {str(e)}")  # Debug information


# Add this function to verify the file type and extension
def get_file_extension(file_path):
    """Get the original file extension from the encrypted file path"""
    # Remove .encrypted extension first
    base_path = file_path.replace('.encrypted', '')
    # Get the actual file extension
    return os.path.splitext(base_path)[1]
def calculate_file_hash(file_path):
    """Calculate SHA-256 hash of file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_secure_directory():
    """Get a secure, hidden directory based on the operating system"""
    if platform.system() == "Windows":
        base_dir = os.path.expanduser("~")
        secure_dir = os.path.join(base_dir, "AppData", "Local", ".evidence_vault")
    else:  # Unix-like systems (Linux, macOS)
        secure_dir = os.path.expanduser("~/.evidence_vault")
    
    if not os.path.exists(secure_dir):
        os.makedirs(secure_dir)
    
    # On Windows, set the hidden attribute
    if platform.system() == "Windows":
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(secure_dir, 2)  # 2 is the hidden attribute
    
    return secure_dir

def secure_file_copy(source_path, case_number):
    """Securely copy and encrypt file to a hidden directory"""
    secure_dir = get_secure_directory()
    
    # Get original file extension
    original_extension = os.path.splitext(source_path)[1]
    
    # Create filename with case number and preserve original extension
    destination_filename = f"{case_number}{original_extension}.encrypted"
    destination_path = os.path.join(secure_dir, destination_filename)
    
    # Encrypt and save file
    encrypted_data = encrypt_file(source_path, ENCRYPTION_KEY)
    with open(destination_path, "wb") as file:
        file.write(encrypted_data)
    
    return destination_path

def encrypt_file(file_path, key):
    """Encrypt a file using Fernet symmetric encryption"""
    f = Fernet(key)
    with open(file_path, "rb") as file:
        file_data = file.read()
    encrypted_data = f.encrypt(file_data)
    return encrypted_data

def decrypt_file(encrypted_file_path, key):
    """Decrypt a file using Fernet symmetric encryption"""
    f = Fernet(key)
    with open(encrypted_file_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data

def show_forensic_investigator_dashboard():
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#E74C3C", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#E74C3C", borderwidth=0)
    home_button.pack(side=tk.LEFT, padx=10)

    view_button = tk.Button(nav_frame, text="View", bg="white", fg="#666", borderwidth=0, command=show_forensic_view_page)
    view_button.pack(side=tk.LEFT, padx=10)

    analyze_button = tk.Button(nav_frame, text="Analyze", bg="white", fg="#666", borderwidth=0)
    analyze_button.pack(side=tk.LEFT, padx=10)

    report_button = tk.Button(nav_frame, text="Report", bg="white", fg="#666", borderwidth=0)
    report_button.pack(side=tk.LEFT, padx=10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=logout)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Main content area
    content_frame = tk.Frame(root, bg="#f5f5f5")
    content_frame.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)

    welcome_label = tk.Label(content_frame, text="Welcome, Forensic Investigator", font=("Arial", 24, "bold"), fg="#E74C3C", bg="#f5f5f5")
    welcome_label.pack(pady=20)

    instructions_label = tk.Label(content_frame, text="Select an option from the navigation menu to begin.", font=("Arial", 14), fg="#666", bg="#f5f5f5")
    instructions_label.pack(pady=10)

    # You can add more widgets or functionality specific to the forensic investigator dashboard here

def show_forensic_view_page():
    for widget in root.winfo_children():
        widget.destroy()

    # Header
    header_frame = tk.Frame(root, bg="white")
    header_frame.pack(fill=tk.X, padx=20, pady=20)

    logo_label = tk.Label(header_frame, text="EVIDENCE VAULT", font=("Arial", 24, "bold"), fg="#E74C3C", bg="white")
    logo_label.pack(side=tk.LEFT)

    tagline_label = tk.Label(header_frame, text="EVIDENCE PROTECTION USING CRYPTOGRAPHY", font=("Arial", 12), fg="#666", bg="white")
    tagline_label.pack(side=tk.LEFT, padx=(10, 0))

    # Navigation
    nav_frame = tk.Frame(header_frame, bg="white")
    nav_frame.pack(side=tk.RIGHT)

    home_button = tk.Button(nav_frame, text="Home", bg="white", fg="#666", borderwidth=0, command=show_forensic_investigator_dashboard)
    home_button.pack(side=tk.LEFT, padx=10)

    view_button = tk.Button(nav_frame, text="View", bg="white", fg="#E74C3C", borderwidth=0)
    view_button.pack(side=tk.LEFT, padx=10)

    analyze_button = tk.Button(nav_frame, text="Analyze", bg="white", fg="#666", borderwidth=0)
    analyze_button.pack(side=tk.LEFT, padx=10)

    report_button = tk.Button(nav_frame, text="Report", bg="white", fg="#666", borderwidth=0)
    report_button.pack(side=tk.LEFT, padx=10)

    logout_button = tk.Button(nav_frame, text="Logout", bg="white", fg="#666", borderwidth=0, command=logout)
    logout_button.pack(side=tk.LEFT, padx=10)

    # Search Container
    search_frame = tk.Frame(root, bg="#f5f5f5")
    search_frame.pack(pady=20)

    search_box = tk.Frame(search_frame, bg="white", relief="solid", borderwidth=1)
    search_box.pack(padx=20, pady=10)

    # Search Entry with placeholder
    search_entry = tk.Entry(search_box, width=40, font=("Arial", 12))
    search_entry.insert(0, "Search Case number")
    search_entry.config(fg='grey')
    search_entry.pack(side=tk.LEFT, padx=10, pady=10)

    def on_entry_click(event):
        if search_entry.get() == "Search Case number":
            search_entry.delete(0, tk.END)
            search_entry.config(fg='black')

    def on_focusout(event):
        if search_entry.get() == "":
            search_entry.insert(0, "Search Case number")
            search_entry.config(fg='grey')

    search_entry.bind('<FocusIn>', on_entry_click)
    search_entry.bind('<FocusOut>', on_focusout)

    # Search Button with functionality
    search_button = tk.Button(search_box, text="🔍", bg="white", fg="#666", 
                             borderwidth=0, font=("Arial", 12), command=lambda: forensic_search_case(search_entry.get()))
    search_button.pack(side=tk.LEFT, padx=(0, 10))

    # Results Frame
    global forensic_search_results_frame
    forensic_search_results_frame = tk.Frame(root, bg="#f5f5f5")
    forensic_search_results_frame.pack(pady=20, fill=tk.BOTH, expand=True, padx=40)

    # Create a separate frame for headings
    headings_frame = tk.Frame(forensic_search_results_frame, bg="#f5f5f5", name="heading_frame")
    headings_frame.pack(fill=tk.X, pady=(0, 10))

    # Configure columns to be evenly spaced
    for i in range(5):
        headings_frame.grid_columnconfigure(i, weight=1)

    # Headings with improved styling
    headings = ["Uploaded Date", "Uploaded Time", "Case Number", "Case Name", "Actions"]
    for i, heading in enumerate(headings):
        heading_label = tk.Label(
            headings_frame, 
            text=heading, 
            font=("Arial", 12, "bold"), 
            bg="#f5f5f5", 
            fg="#333"
        )
        heading_label.grid(row=0, column=i, padx=5, pady=5, sticky="nsew")

    # Ensure the results frame is ready for displaying results
    forensic_search_results_frame.grid_rowconfigure(0, weight=1)
    for i in range(5):
        forensic_search_results_frame.grid_columnconfigure(i, weight=1)

    print("Debug: Forensic view page set up completed")


    # Add a separator line
    separator = tk.Frame(forensic_search_results_frame, height=2, bg="#cccccc")
    separator.pack(fill=tk.X, pady=(0, 10))

headings = ["Uploaded Date", "Uploaded Time", "Case Number", "Case Name", "Actions"]

def forensic_search_case(case_number):
    print(f"Searching for case number: {case_number}")

    # Clear previous results except the headings
    for widget in forensic_search_results_frame.winfo_children():
        if widget.winfo_name() != "heading_frame":  # Keep the heading frame
            widget.destroy()

    if not case_number or case_number == "Search Case number":
        print("No case number entered")
        return

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        query = 'SELECT upload_date, case_number, case_name, file_path FROM uploads WHERE case_number=?'
        c.execute(query, (case_number,))
        results = c.fetchall()

        # Create a new frame for results
        results_container = tk.Frame(forensic_search_results_frame, bg="#f5f5f5")
        results_container.pack(fill=tk.BOTH, expand=True)

        # Configure columns in results container
        for i in range(5):
            results_container.grid_columnconfigure(i, weight=1)
        
        if results:
            for i, (upload_date, case_number, case_name, file_path) in enumerate(results, start=0):
                try:
                    date_obj = datetime.strptime(upload_date, '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    date_obj = datetime.strptime(upload_date, '%Y-%m-%d %H:%M:%S')
                uploaded_date = date_obj.strftime('%Y-%m-%d')
                uploaded_time = date_obj.strftime('%H:%M:%S')
                
                # Create result labels with consistent styling
                tk.Label(
                    results_container, 
                    text=uploaded_date, 
                    bg="#f5f5f5",
                    fg="#333",
                    padx=15,
                    pady=8
                ).grid(row=i, column=0, sticky="nsew")
                
                tk.Label(
                    results_container, 
                    text=uploaded_time, 
                    bg="#f5f5f5",
                    fg="#333",
                    padx=15,
                    pady=8
                ).grid(row=i, column=1, sticky="nsew")
                
                tk.Label(
                    results_container, 
                    text=case_number, 
                    bg="#f5f5f5",
                    fg="#333",
                    padx=15,
                    pady=8
                ).grid(row=i, column=2, sticky="nsew")
                
                tk.Label(
                    results_container, 
                    text=case_name, 
                    bg="#f5f5f5",
                    fg="#333",
                    padx=15,
                    pady=8
                ).grid(row=i, column=3, sticky="nsew")
                
                # Create a frame for buttons
                button_frame = tk.Frame(results_container, bg="#f5f5f5")
                button_frame.grid(row=i, column=4, sticky="nsew", padx=5, pady=5)
                
                view_button = tk.Button(
                    button_frame, 
                    text="View",
                    command=lambda fp=file_path: open_file(fp),
                    bg="#E74C3C",
                    fg="white",
                    padx=10,
                    pady=2
                )
                view_button.pack(side=tk.LEFT, padx=2)

        else:
            no_results_label = tk.Label(
                results_container, 
                text="No Matches Found", 
                fg="red", 
                bg="#f5f5f5",
                font=("Arial", 12),
                pady=20
            )
            no_results_label.grid(row=0, column=0, columnspan=5, sticky="nsew")

    except sqlite3.Error as e:
        print(f"Database error: {e}")
        messagebox.showerror("Database Error", f"An error occurred: {str(e)}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        messagebox.showerror("Error", f"An unexpected error occurred: {str(e)}")
    finally:
        if conn:
            conn.close()

def open_forensic_file(file_path):
    # Logic to decrypt and open the forensic file
    print(f"Opening forensic file: {file_path}")
    # Implement the decryption and file opening logic here

def logout():
    global current_user_id
    current_user_id = None
    show_login()

if __name__ == "__main__":
    create_database()
    verify_database_structure()
    
    root = tk.Tk()
    root.title("Evidence Vault")
    root.geometry("800x600")
    
    create_login_frame()
    
    root.mainloop()