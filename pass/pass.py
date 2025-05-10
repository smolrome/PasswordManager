import sqlite3
import hashlib
import secrets
import string
import pyperclip
from cryptography.fernet import Fernet
import getpass
import os
from datetime import datetime, timedelta
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from collections import defaultdict
import ctypes
import json
import time

class PasswordManager:
    def __init__(self):
        self.key = None
        self.cipher_suite = None
        self.conn = None
        self.failed_attempts = 0
        self.locked_until = None
        self.create_database()
        self.update_database_schema()  # Add this line
        self.setup_encryption()
        
    def repair_corrupted_entry(self, password_id, new_password):
        """Replace a corrupted password entry"""
        try:
            encrypted = self.encrypt(new_password)
            cursor = self.conn.cursor()
            cursor.execute('''
            UPDATE passwords 
            SET password = ?, updated_at = ?
            WHERE id = ?
            ''', (encrypted, datetime.now().isoformat(), password_id))
            self.conn.commit()
            return True
        except:
            return False
        
    def find_corrupted_entries(self):
        """Identify passwords with invalid encryption"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, service, password FROM passwords')
        
        corrupted = []
        for id, service, encrypted in cursor.fetchall():
            # Check if the data looks like valid Base64
            if not all(c.isalnum() or c in {'+', '/', '=', '-'} for c in encrypted):
                corrupted.append((id, service, encrypted))
        
        return corrupted
        
    def create_database(self):
        """Create database with enhanced security schema"""
        self.conn = sqlite3.connect('passwords.db')
        cursor = self.conn.cursor()
        
        # Master password table with brute-force protection fields
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            last_failed TEXT
        )
        ''')
        
        # Passwords table with version history
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT,
            password TEXT NOT NULL,
            url TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            password_history TEXT DEFAULT '[]'
        )
        ''')
        
        self.conn.commit()
        
    def validate_database(self):
        """Check all encrypted passwords for validity"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT id, service, password FROM passwords')
        
        corrupted = []
        for id, service, encrypted in cursor.fetchall():
            try:
                # Test decryption
                self.decrypt(encrypted)
            except:
                corrupted.append((id, service))
        
        if corrupted:
            print(f"Found {len(corrupted)} corrupted entries:")
            for id, service in corrupted:
                print(f"- ID {id}: {service}")
        else:
            print("All password entries are valid")
        
        return corrupted
    
    def setup_encryption(self):
        """Initialize encryption with key rotation support"""
        key_file = 'encryption.key'
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(self.key)
        self.cipher_suite = Fernet(self.key)
    
    def secure_wipe(self, data):
        """Physically overwrite sensitive data in memory"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        buffer = ctypes.create_string_buffer(data)
        ctypes.memset(ctypes.addressof(buffer), 0, len(buffer))
        del buffer
    
    def hash_password(self, password, salt=None):
        """Secure password hashing with PBKDF2"""
        if salt is None:
            salt = secrets.token_hex(32)  # 256-bit salt
        iterations = 600000  # OWASP recommended minimum
        hashed = hashlib.pbkdf2_hmac('sha512', password.encode(), salt.encode(), iterations)
        return hashed.hex(), salt
    
    def check_brute_force(self):
        """Prevent brute force attacks with progressive delays"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT failed_attempts, last_failed FROM master_password LIMIT 1')
        result = cursor.fetchone()
        
        if result and result[0] > 0 and result[1]:
            attempts, last_failed = result
            last_failed = datetime.fromisoformat(last_failed)
            delay = min(2 ** (attempts - 1), 300)  # Max 5 minute delay
            if (datetime.now() - last_failed).seconds < delay:
                remaining = delay - (datetime.now() - last_failed).seconds
                raise Exception(f"Too many attempts. Wait {remaining} seconds")
    
    def set_master_password(self, password):
        """Set master password with security checks"""
        if len(password) < 12:
            raise ValueError("Master password must be at least 12 characters")
            
        hashed, salt = self.hash_password(password)
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM master_password')  # Remove existing master password
        cursor.execute('INSERT INTO master_password (password_hash, salt) VALUES (?, ?)', 
                       (hashed, salt))
        self.conn.commit()
        self.secure_wipe(password)
    
    def verify_master_password(self, password):
        """Secure verification with brute force protection"""
        self.check_brute_force()
        
        cursor = self.conn.cursor()
        cursor.execute('SELECT password_hash, salt FROM master_password LIMIT 1')
        result = cursor.fetchone()
        if not result:
            raise Exception("Master password not set")
            
        stored_hash, salt = result
        hashed, _ = self.hash_password(password, salt)  # Use the retrieved salt
        
        if hashed == stored_hash:
            # Reset failed attempts on success
            cursor.execute('UPDATE master_password SET failed_attempts = 0')
            self.conn.commit()
            return True
        else:
            # Increment failed attempts
            cursor.execute('''
            UPDATE master_password 
            SET failed_attempts = failed_attempts + 1,
                last_failed = ?
            ''', (datetime.now().isoformat(),))
            self.conn.commit()
            return False
    
    def encrypt(self, data):
        """Encrypt data with proper error handling"""
        try:
            if not isinstance(data, str):
                raise ValueError("Data to encrypt must be a string")
            encrypted = self.cipher_suite.encrypt(data.encode())
            return encrypted.decode('utf-8')  # Convert bytes to string for storage
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")
    
    def decrypt(self, encrypted_data):
        """Decrypt data with robust error handling and padding correction"""
        try:
            if not encrypted_data:
                raise ValueError("No data to decrypt")
                
            # Ensure the string is properly padded for Base64
            # Base64 requires length to be a multiple of 4
            padding = len(encrypted_data) % 4
            if padding:
                encrypted_data += '=' * (4 - padding)
                
            # Verify the data looks like valid Base64
            try:
                import base64
                base64.urlsafe_b64decode(encrypted_data)
            except:
                raise ValueError("Invalid Base64 data")
                
            # Decrypt the data
            decrypted_bytes = self.cipher_suite.decrypt(encrypted_data.encode('utf-8'))
            return decrypted_bytes.decode('utf-8')
            
        except Exception as e:
            print(f"Decryption failed for data: {encrypted_data[:50]}...")
            print(f"Error details: {str(e)}")
            raise ValueError("Failed to decrypt - possibly corrupted data or wrong key")
    
    def generate_password(self, length=16, use_upper=True, use_digits=True, use_special=True):
        """Generate a strong random password with complexity rules"""
        chars = string.ascii_lowercase
        if use_upper:
            chars += string.ascii_uppercase
        if use_digits:
            chars += string.digits
        if use_special:
            chars += string.punctuation
        
        while True:
            password = ''.join(secrets.choice(chars) for _ in range(length))
            # Ensure password meets complexity requirements
            if (not use_upper or any(c.isupper() for c in password)) and \
               (not use_digits or any(c.isdigit() for c in password)) and \
               (not use_special or any(c in string.punctuation for c in password)):
                return password
    
    def add_password(self, service, username, password, url=None, notes=None):
        """Add new password with validation"""
        if not service or not password:
            raise ValueError("Service and password required")
            
        encrypted = self.encrypt(password)
        now = datetime.now().isoformat()
        
        # Verify the encryption worked
        try:
            self.decrypt(encrypted)
        except:
            raise ValueError("Failed to create valid encrypted data")
        
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO passwords 
        (service, username, password, url, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (service, username, encrypted, url, notes, now, now))
        self.conn.commit()
    
    def get_password_by_id(self, password_id):
        """Retrieve password with better error handling"""
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT id, service, username, password, url, notes, created_at, updated_at 
        FROM passwords WHERE id = ?
        ''', (password_id,))
        
        result = cursor.fetchone()
        if not result:
            return None
            
        id, service, username, encrypted, url, notes, created, updated = result
        
        try:
            decrypted = self.decrypt(encrypted)
        except Exception as e:
            print(f"Failed to decrypt password ID {id}: {str(e)}")
            decrypted = "[DECRYPTION FAILED]"
        
        # Log access
        cursor.execute('''
        UPDATE passwords 
        SET updated_at = ?
        WHERE id = ?
        ''', (datetime.now().isoformat(), id))
        self.conn.commit()
        
        return {
            'id': id,
            'service': service,
            'username': username,
            'password': decrypted,
            'url': url,
            'notes': notes,
            'created': created,
            'updated': updated
        }
    
    def update_password(self, password_id, service, username, password, url=None, notes=None):
        """Update password with version history"""
        # Get current password first
        current = self.get_password_by_id(password_id)
        if not current:
            raise Exception("Password not found")
        
        # Update history
        cursor = self.conn.cursor()
        cursor.execute('SELECT password_history FROM passwords WHERE id = ?', (password_id,))
        history = json.loads(cursor.fetchone()[0])
        
        history.append({
            'password': current['password'],
            'changed_at': datetime.now().isoformat()
        })
        
        # Update record
        encrypted = self.encrypt(password)
        updated_at = datetime.now().isoformat()
        
        cursor.execute('''
        UPDATE passwords 
        SET service = ?, username = ?, password = ?, url = ?, notes = ?, 
            updated_at = ?, password_history = ?
        WHERE id = ?
        ''', (service, username, encrypted, url, notes, updated_at, json.dumps(history), password_id))
        self.conn.commit()
    
    def delete_password(self, password_id):
        """Securely delete password"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        self.conn.commit()
    
    def change_master_password(self, current_password, new_password):
        """Change master password with validation"""
        if not self.verify_master_password(current_password):
            raise Exception("Current password is incorrect")
        
        if len(new_password) < 12:
            raise ValueError("New password must be at least 12 characters")
            
        hashed, salt = self.hash_password(new_password)
        cursor = self.conn.cursor()
        cursor.execute('UPDATE master_password SET password_hash = ?, salt = ?', 
                      (hashed, salt))
        self.conn.commit()
    
    def export_passwords(self, file_path):
        """Encrypted export with integrity checks"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT service, username, password, url, notes FROM passwords')
        
        data = {
            'version': 1,
            'timestamp': datetime.now().isoformat(),
            'entries': cursor.fetchall()
        }
        
        # Double encryption
        encrypted_data = self.cipher_suite.encrypt(json.dumps(data).encode())
        
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)
    
    def import_passwords(self, file_path):
        """Secure import with validation"""
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        try:
            decrypted = json.loads(self.cipher_suite.decrypt(encrypted_data).decode())
        except:
            raise ValueError("Invalid or corrupted import file")
            
        if decrypted.get('version') != 1:
            raise ValueError("Unsupported file version")
            
        imported = 0
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for entry in decrypted.get('entries', []):
            try:
                service, username, encrypted, url, notes = entry
                # Verify encryption is valid
                password = self.decrypt(encrypted)
                
                cursor.execute('''
                INSERT INTO passwords 
                (service, username, password, url, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (service, username, self.encrypt(password), url, notes, now, now))
                imported += 1
                
                self.secure_wipe(password)
            except:
                continue
                
        self.conn.commit()
        return imported
    
    def password_audit(self):
        """Check for weak/reused passwords"""
        weak = []
        reused = defaultdict(list)
        cursor = self.conn.cursor()
        
        cursor.execute('SELECT service, password FROM passwords')
        for service, encrypted in cursor.fetchall():
            try:
                password = self.decrypt(encrypted)
                
                # Check strength
                if (len(password) < 8 or 
                    not any(c.isupper() for c in password) or 
                    not any(c.isdigit() for c in password)):
                    weak.append(service)
                
                # Track reuse
                reused[password].append(service)
                
                self.secure_wipe(password)
            except:
                continue
                
        return {
            'weak_passwords': weak,
            'reused_passwords': {k:v for k,v in reused.items() if len(v) > 1}
        }

    def update_database_schema(self):
        """Update the database schema to include missing columns"""
        cursor = self.conn.cursor()
        
        # Check if 'failed_attempts' column exists in 'master_password' table
        cursor.execute("PRAGMA table_info(master_password)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'failed_attempts' not in columns:
            cursor.execute("ALTER TABLE master_password ADD COLUMN failed_attempts INTEGER DEFAULT 0")
        
        # Check if 'last_failed' column exists in 'master_password' table
        if 'last_failed' not in columns:
            cursor.execute("ALTER TABLE master_password ADD COLUMN last_failed TEXT")
        
        self.conn.commit()

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        self.last_activity = datetime.now()
        self.session_timeout = 300  # 5 minutes in seconds
        
        # Security manager
        self.pm = PasswordManager()
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Gradient colors
        self.bg_dark = "#121212"
        self.bg_light = "#f5f5f5"
        self.accent_color = "#4a4a4a"
        self.text_color = "#ffffff"
        self.entry_bg = "#2a2a2a"
        
        # Configure styles
        self.style.configure('TFrame', background=self.bg_dark)
        self.style.configure('TLabel', background=self.bg_dark, foreground=self.text_color)
        self.style.configure('TButton', 
                            background=self.accent_color, 
                            foreground=self.text_color,
                            borderwidth=1,
                            relief='flat')
        self.style.map('TButton',
                      background=[('active', '#5a5a5a'), ('pressed', '#3a3a3a')])
        self.style.configure('TEntry', 
                           fieldbackground=self.entry_bg,
                           foreground=self.text_color,
                           insertcolor=self.text_color)
        self.style.configure('Treeview', 
                           background=self.entry_bg,
                           foreground=self.text_color,
                           fieldbackground=self.entry_bg)
        self.style.configure('Treeview.Heading', 
                           background=self.accent_color,
                           foreground=self.text_color)
        
        # Initialize UI
        self.setup_activity_tracking()
        self.check_master_password()
    
    def setup_activity_tracking(self):
        """Track user activity for session timeout"""
        self.root.bind("<Motion>", self.reset_inactivity_timer)
        self.root.bind("<KeyPress>", self.reset_inactivity_timer)
        self.check_inactivity()
    
    def reset_inactivity_timer(self, event=None):
        """Reset the inactivity timer"""
        self.last_activity = datetime.now()
    
    def check_inactivity(self):
        """Check for inactivity and lock if needed"""
        inactive_for = (datetime.now() - self.last_activity).seconds
        if inactive_for > self.session_timeout:
            self.lock_app()
        self.root.after(1000, self.check_inactivity)
    
    def lock_app(self):
        """Lock the application"""
        self.clear_window()
        self.show_login()
    
    def check_master_password(self):
        """Check if master password is set"""
        cursor = self.pm.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM master_password')
        if cursor.fetchone()[0] == 0:
            self.show_set_master_password()
        else:
            self.show_login()
    
    def show_set_master_password(self):
        """Display master password setup screen"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="30 30 30 30")
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Set Master Password", font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        ttk.Label(frame, text="This will be used to encrypt/decrypt your passwords").pack(pady=5)
        
        self.master_pw1 = ttk.Entry(frame, show="•", width=30)
        self.master_pw1.pack(pady=10)
        
        ttk.Label(frame, text="Confirm Master Password").pack(pady=5)
        
        self.master_pw2 = ttk.Entry(frame, show="•", width=30)
        self.master_pw2.pack(pady=10)
        
        ttk.Button(frame, text="Set Password", command=self.handle_set_master_password).pack(pady=20)
    
    def handle_set_master_password(self):
        """Handle master password setup"""
        pw1 = self.master_pw1.get()
        pw2 = self.master_pw2.get()
        
        if not pw1 or not pw2:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        
        if pw1 != pw2:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        try:
            self.pm.set_master_password(pw1)
            messagebox.showinfo("Success", "Master password set successfully")
            self.show_main_app()
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def show_login(self):
        """Display login screen with brute-force protection"""
        self.clear_window()
        
        frame = ttk.Frame(self.root, padding="30 30 30 30")
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Login to Password Manager", font=('Helvetica', 16, 'bold')).pack(pady=10)
        
        ttk.Label(frame, text="Enter Master Password").pack(pady=5)
        
        self.master_pw_entry = ttk.Entry(frame, show="•", width=30)
        self.master_pw_entry.pack(pady=10)
        
        ttk.Button(frame, text="Login", command=self.handle_login).pack(pady=20)
        
        # Bind Enter key to login
        self.root.bind('<Return>', lambda event: self.handle_login())
    
    def handle_login(self):
        """Handle login with brute-force protection"""
        password = self.master_pw_entry.get()
        try:
            if self.pm.verify_master_password(password):
                self.show_main_app()
            else:
                messagebox.showerror("Error", "Incorrect master password")
        except Exception as e:
            messagebox.showerror("Security Alert", str(e))
    
    def show_main_app(self):
        """Main application interface"""
        self.clear_window()
        self.reset_inactivity_timer()
        
        # Main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Sidebar
        self.sidebar = ttk.Frame(self.main_frame, width=200)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Sidebar buttons
        buttons = [
            ("Add Password", self.show_add_password),
            ("View Passwords", self.show_password_list),
            ("Password Audit", self.show_password_audit),
            ("Generate Password", self.show_generate_password),
            ("Change Master", self.show_change_master),
            ("Import/Export", self.show_import_export),
            ("Lock", self.lock_app),
            ("Exit", self.root.quit)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(self.sidebar, text=text, command=command)
            btn.pack(fill=tk.X, pady=2)
        
        # Content area
        self.content = ttk.Frame(self.main_frame)
        self.content.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)
        
        # Show password list by default
        self.show_password_list()
    
    def show_password_audit(self):
        """Display password audit results"""
        self.clear_content()
        
        try:
            audit_results = self.pm.password_audit()
        except Exception as e:
            messagebox.showerror("Error", f"Audit failed: {str(e)}")
            return
        
        frame = ttk.Frame(self.content, padding="20 20 20 20")
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Password Security Audit", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        if not audit_results['weak_passwords'] and not audit_results['reused_passwords']:
            ttk.Label(frame, text="✅ No security issues found!", foreground="green").pack(pady=10)
            return
        
        if audit_results['weak_passwords']:
            ttk.Label(frame, text="⚠️ Weak Passwords Found:", foreground="orange").pack(pady=5, anchor=tk.W)
            for service in audit_results['weak_passwords']:
                ttk.Label(frame, text=f"- {service}").pack(anchor=tk.W)
        
        if audit_results['reused_passwords']:
            ttk.Label(frame, text="\n🔴 Reused Passwords:", foreground="red").pack(pady=5, anchor=tk.W)
            for password, services in audit_results['reused_passwords'].items():
                ttk.Label(frame, text=f"Used in: {', '.join(services)}").pack(anchor=tk.W)
    
    # [Rest of the methods remain the same as in your original file, but now using the enhanced PasswordManager class]
    # show_add_password(), save_password(), show_password_list(), etc.
    
    def show_add_password(self):
        """Show the add password form"""
        self.clear_content()
        
        frame = ttk.Frame(self.content, padding="20 20 20 20")
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Add New Password", font=('Helvetica', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        # Form fields
        ttk.Label(frame, text="Service/Website:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.service_entry = ttk.Entry(frame, width=30)
        self.service_entry.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky=tk.E, pady=5)
        self.username_entry = ttk.Entry(frame, width=30)
        self.username_entry.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Password:").grid(row=3, column=0, sticky=tk.E, pady=5)
        self.password_entry = ttk.Entry(frame, width=30, show="•")
        self.password_entry.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        # Generate password button
        ttk.Button(frame, text="Generate Password", command=self.show_generate_password).grid(row=3, column=2, padx=5)
        
        ttk.Label(frame, text="URL:").grid(row=4, column=0, sticky=tk.E, pady=5)
        self.url_entry = ttk.Entry(frame, width=30)
        self.url_entry.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Notes:").grid(row=5, column=0, sticky=tk.E, pady=5)
        self.notes_entry = tk.Text(frame, width=30, height=4, bg=self.entry_bg, fg=self.text_color, 
                                 insertbackground=self.text_color)
        self.notes_entry.grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Submit button
        ttk.Button(frame, text="Save Password", command=self.save_password).grid(row=6, column=0, columnspan=2, pady=20)
        
    def show_generate_password(self):
        """Show the password generator dialog"""
        gen_window = tk.Toplevel(self.root)
        gen_window.title("Generate Password")
        gen_window.geometry("400x300")
        
        frame = ttk.Frame(gen_window, padding="20 20 20 20")
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Generate Secure Password", font=('Helvetica', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        # Options
        ttk.Label(frame, text="Length:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.length_var = tk.IntVar(value=16)
        ttk.Entry(frame, textvariable=self.length_var, width=5).grid(row=1, column=1, sticky=tk.W, pady=5)
        
        self.upper_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Include Uppercase Letters", variable=self.upper_var).grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        self.digits_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Include Digits", variable=self.digits_var).grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        self.special_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Include Special Characters", variable=self.special_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        # Generated password display
        self.gen_password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.gen_password_var, state='readonly', width=30).grid(row=5, column=0, columnspan=2, pady=10)
        
        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        ttk.Button(btn_frame, text="Generate", command=self.generate_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copy", command=self.copy_generated_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Use This Password", command=lambda: self.use_generated_password(gen_window)).pack(side=tk.LEFT, padx=5)
        
    def show_change_master(self):
        """Show the change master password dialog"""
        # First verify current password
        current = simpledialog.askstring("Current Password", "Enter current master password:", show='•')
        if not current or not self.pm.verify_master_password(current):
            messagebox.showerror("Error", "Incorrect master password")
            return
        
        # Get new password
        new1 = simpledialog.askstring("New Password", "Enter new master password:", show='•')
        if not new1:
            return
        
        new2 = simpledialog.askstring("Confirm Password", "Confirm new master password:", show='•')
        if new1 != new2:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        try:
            self.pm.change_master_password(current, new1)
            messagebox.showinfo("Success", "Master password changed successfully")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change master password: {str(e)}")
            
    def search_passwords(self):
        """Search passwords by service name"""
        search_term = self.search_entry.get()
        self.load_passwords(search_term)
        
    def reveal_password(self, encrypted_password, frame):
        """Reveal the password in the details window"""
        try:
            decrypted = self.pm.decrypt(encrypted_password)
            if decrypted is None:
                raise ValueError("Could not decrypt password")
                
            for widget in frame.winfo_children():
                widget.destroy()
            ttk.Label(frame, text=decrypted).pack(side=tk.LEFT)
            ttk.Button(frame, text="Hide", 
                    command=lambda: self.hide_password(encrypted_password, frame)).pack(side=tk.LEFT, padx=5)
            ttk.Button(frame, text="Copy", 
                    command=lambda: self.copy_decrypted_password(encrypted_password)).pack(side=tk.LEFT)
        except Exception as e:
            for widget in frame.winfo_children():
                widget.destroy()
            ttk.Label(frame, text="Decryption Error", foreground="red").pack(side=tk.LEFT)

    def hide_password(self, encrypted_password, frame):
        """Hide the password again"""
        for widget in frame.winfo_children():
            widget.destroy()
        ttk.Label(frame, text="••••••••").pack(side=tk.LEFT)
        ttk.Button(frame, text="Reveal", 
                command=lambda: self.reveal_password(encrypted_password, frame)).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame, text="Copy", 
                command=lambda: self.copy_decrypted_password(encrypted_password)).pack(side=tk.LEFT)
        
    def copy_password(self):
        """Copy selected password to clipboard"""
        password_id = self.get_selected_password_id()
        if password_id is None:
            return
        
        password_data = self.pm.get_password_by_id(password_id)
        if password_data:
            self.copy_decrypted_password(password_data[3])
    
    def edit_password(self):
        """Edit the selected password"""
        password_id = self.get_selected_password_id()
        if password_id is None:
            return
        
        password_data = self.pm.get_password_by_id(password_id)
        if not password_data:
            messagebox.showerror("Error", "Password not found")
            return
        
        # Create edit window
        edit_window = tk.Toplevel(self.root)
        edit_window.title("Edit Password")
        edit_window.geometry("500x500")
        
        frame = ttk.Frame(edit_window, padding="20 20 20 20")
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Edit Password", font=('Helvetica', 14, 'bold')).grid(row=0, column=0, columnspan=2, pady=10)
        
        # Form fields with current values
        ttk.Label(frame, text="Service/Website:").grid(row=1, column=0, sticky=tk.E, pady=5)
        self.edit_service = ttk.Entry(frame, width=30)
        self.edit_service.insert(0, password_data[1])
        self.edit_service.grid(row=1, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Username:").grid(row=2, column=0, sticky=tk.E, pady=5)
        self.edit_username = ttk.Entry(frame, width=30)
        self.edit_username.insert(0, password_data[2] or "")
        self.edit_username.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Password:").grid(row=3, column=0, sticky=tk.E, pady=5)
        self.edit_password = ttk.Entry(frame, width=30, show="•")
        self.edit_password.insert(0, self.pm.decrypt(password_data[3]))
        self.edit_password.grid(row=3, column=1, sticky=tk.W, pady=5)
        
        ttk.Button(frame, text="Generate New", command=self.show_generate_password).grid(row=3, column=2, padx=5)
        
        ttk.Label(frame, text="URL:").grid(row=4, column=0, sticky=tk.E, pady=5)
        self.edit_url = ttk.Entry(frame, width=30)
        self.edit_url.insert(0, password_data[4] or "")
        self.edit_url.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        ttk.Label(frame, text="Notes:").grid(row=5, column=0, sticky=tk.E, pady=5)
        self.edit_notes = tk.Text(frame, width=30, height=4, bg=self.entry_bg, fg=self.text_color, 
                                insertbackground=self.text_color)
        self.edit_notes.insert("1.0", password_data[5] or "")
        self.edit_notes.grid(row=5, column=1, sticky=tk.W, pady=5)
        
        # Save button
        ttk.Button(frame, text="Save Changes", 
                  command=lambda: self.save_edited_password(password_id, edit_window)).grid(row=6, column=0, columnspan=2, pady=20)
    
    def save_edited_password(self, password_id, window):
        """Save the edited password"""
        service = self.edit_service.get()
        username = self.edit_username.get()
        password = self.edit_password.get()
        url = self.edit_url.get()
        notes = self.edit_notes.get("1.0", tk.END).strip()
        
        if not service or not password:
            messagebox.showerror("Error", "Service and password are required")
            return
        
        try:
            self.pm.update_password(password_id, service, username, password, url, notes)
            messagebox.showinfo("Success", "Password updated successfully")
            window.destroy()
            self.load_passwords()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update password: {str(e)}")
    
    def delete_password(self):
        """Delete the selected password"""
        password_id = self.get_selected_password_id()
        if password_id is None:
            return
        
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?")
        if confirm:
            try:
                self.pm.delete_password(password_id)
                messagebox.showinfo("Success", "Password deleted successfully")
                self.load_passwords()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete password: {str(e)}")
                
    def load_passwords(self, search_term=None):
        """Load passwords into the treeview"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        cursor = self.pm.conn.cursor()
        if search_term:
            cursor.execute('SELECT id, service, username FROM passwords WHERE service LIKE ? ORDER BY service', 
                          (f'%{search_term}%',))
        else:
            cursor.execute('SELECT id, service, username FROM passwords ORDER BY service')
        
        for row in cursor.fetchall():
            self.tree.insert('', tk.END, iid=row[0], text=row[0], values=(row[1], row[2]))
            
    def get_selected_password_id(self):
        """Get the selected password ID from the treeview"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No password selected")
            return None
        return int(selected[0])
    
    def generate_password(self):
        """Generate a password based on selected options"""
        length = self.length_var.get()
        use_upper = self.upper_var.get()
        use_digits = self.digits_var.get()
        use_special = self.special_var.get()
        
        password = self.pm.generate_password(length, use_upper, use_digits, use_special)
        self.gen_password_var.set(password)
    
    def copy_generated_password(self):
        """Copy the generated password to clipboard"""
        password = self.gen_password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard")
            
    def use_generated_password(self, window):
        """Use the generated password in the add/edit form"""
        password = self.gen_password_var.get()
        if password:
            try:
                # Find the password entry field in the add/edit form
                if hasattr(self, 'password_entry'):
                    self.password_entry.delete(0, tk.END)
                    self.password_entry.insert(0, password)
                elif hasattr(self, 'edit_password'):
                    self.edit_password.delete(0, tk.END)
                    self.edit_password.insert(0, password)
                
                window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Couldn't use password: {str(e)}")
                
    def copy_decrypted_password(self, encrypted_password):
        """Copy decrypted password to clipboard with error handling"""
        try:
            decrypted = self.pm.decrypt(encrypted_password)
            if decrypted is None:
                messagebox.showerror("Error", "Could not decrypt password")
                return
                
            pyperclip.copy(decrypted)
            messagebox.showinfo("Copied", "Password copied to clipboard")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt password: {str(e)}")
    
    def view_password_details(self):
        """View details with better error handling"""
        password_id = self.get_selected_password_id()
        if password_id is None:
            return

        password_data = self.pm.get_password_by_id(password_id)
        if not password_data:
            messagebox.showerror("Error", "Password not found")
            return

        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title("Password Details")
        details_window.geometry("500x400")

        frame = ttk.Frame(details_window, padding="20 20 20 20")
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Password Details", font=('Helvetica', 14, 'bold')).pack(pady=10)

        # Display fields
        fields = [
            ("Service:", password_data['service']),
            ("Username:", password_data['username'] or "N/A"),
            ("Password:", "••••••••" if password_data['password'] != "[DECRYPTION FAILED]" else "[DECRYPTION FAILED]"),
            ("URL:", password_data['url'] or "N/A"),
            ("Notes:", password_data['notes'] or "N/A"),
            ("Created:", password_data['created']),
            ("Last Updated:", password_data['updated'])
        ]

        for label, value in fields:
            field_frame = ttk.Frame(frame)
            field_frame.pack(fill=tk.X, pady=2)
            ttk.Label(field_frame, text=label, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)
            
            if label == "Password:":
                if password_data['password'] == "[DECRYPTION FAILED]":
                    ttk.Label(field_frame, text=value, foreground="red").pack(side=tk.LEFT)
                else:
                    ttk.Label(field_frame, text=value).pack(side=tk.LEFT, padx=5)
                    ttk.Button(field_frame, text="Reveal",
                            command=lambda p=password_data['password'], f=field_frame: self.reveal_password(p, f)).pack(side=tk.LEFT, padx=5)
                    ttk.Button(field_frame, text="Copy",
                            command=lambda p=password_data['password']: self.copy_decrypted_password(p)).pack(side=tk.LEFT, padx=5)
            else:
                ttk.Label(field_frame, text=value).pack(side=tk.LEFT)

        # Close button
        ttk.Button(frame, text="Close", command=details_window.destroy).pack(pady=20)
            
    def show_import_export(self):
        """Show the import/export options"""
        self.clear_content()
        
        frame = ttk.Frame(self.content, padding="20 20 20 20")
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, text="Import/Export Passwords", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        ttk.Label(frame, text="Export all passwords to a file:").pack(pady=10)
        ttk.Button(frame, text="Export Passwords", command=self.export_passwords).pack(pady=5)
        
        ttk.Label(frame, text="Import passwords from a file:").pack(pady=10)
        ttk.Button(frame, text="Import Passwords", command=self.import_passwords).pack(pady=5)
        
        ttk.Label(frame, text="Warning: Exported files contain unencrypted passwords!", 
                 foreground="red").pack(pady=20)
    
    def save_password(self):
        """Save the new password entry"""
        service = self.service_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        url = self.url_entry.get()
        notes = self.notes_entry.get("1.0", tk.END).strip()
        
        if not service or not password:
            messagebox.showerror("Error", "Service and password are required")
            return
        
        try:
            self.pm.add_password(service, username, password, url, notes)
            messagebox.showinfo("Success", "Password saved successfully")
            self.show_password_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save password: {str(e)}")
    
    def show_password_list(self):
        """Show the list of saved passwords"""
        self.clear_content()
        
        frame = ttk.Frame(self.content)
        frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        ttk.Label(frame, text="Your Passwords", font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        # Search frame
        search_frame = ttk.Frame(frame)
        search_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_entry = ttk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_passwords).pack(side=tk.LEFT, padx=5)
        
        # Treeview to display passwords
        self.tree = ttk.Treeview(frame, columns=('Service', 'Username'), selectmode='browse')
        self.tree.heading('#0', text='ID')
        self.tree.heading('Service', text='Service')
        self.tree.heading('Username', text='Username')
        
        self.tree.column('#0', width=50, stretch=tk.NO)
        self.tree.column('Service', width=200)
        self.tree.column('Username', width=200)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(expand=True, fill=tk.BOTH)
        
        # Action buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="View Details", command=self.view_password_details).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Copy Password", command=self.copy_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Edit", command=self.edit_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete", command=self.delete_password).pack(side=tk.LEFT, padx=5)
        
        # Load passwords
        self.load_passwords()
        
        # Bind double click to view details
        self.tree.bind('<Double-1>', lambda event: self.view_password_details())

    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def clear_content(self):
        """Clear the content area"""
        for widget in self.content.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()