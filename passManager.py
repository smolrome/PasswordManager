import sqlite3
import hashlib
import secrets
import string
import pyperclip
from cryptography.fernet import Fernet
import getpass
import os
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from PIL import Image, ImageTk
import atexit
import time
from pathlib import Path

def on_program_start():
    """Log when the program starts"""
    print("Program is starting...")

def on_program_exit():
    """Log when the program terminates"""
    print("Program has been terminated.")
    
def program_running():
    print("Program is running...")

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Auto-lock settings (5 minutes default)
        self.idle_timeout = 300  # Seconds
        self.last_activity = time.time()
        self.lock_timer = None
        self.countdown_label = None
        
        # Track if we're currently locked
        self.is_locked = False
        
        # Start monitoring activity
        self.setup_activity_tracking()
        
        # Configure style with black and white gradient
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
        self.style.configure('TCombobox', 
                           fieldbackground=self.entry_bg,
                           foreground=self.text_color)
        self.style.configure('Treeview', 
                           background=self.entry_bg,
                           foreground=self.text_color,
                           fieldbackground=self.entry_bg)
        self.style.configure('Treeview.Heading', 
                           background=self.accent_color,
                           foreground=self.text_color)
        self.style.map('Treeview', 
                      background=[('selected', '#4a4a4a')])
        
        # Create the password manager core
        self.pm = PasswordManager()
        
        # Check if master password is set
        if not self.is_master_password_set():
            self.show_set_master_password()
        else:
            self.show_login()
            
    def setup_activity_tracking(self):
        """Bind events to track user activity"""
        events = ['<Motion>', '<KeyPress>', '<ButtonPress>']
        for event in events:
            self.root.bind(event, self.reset_inactivity_timer)
        
        # Start the countdown check
        self.check_inactivity()

    def reset_inactivity_timer(self, event=None):
        """Reset timer on user activity"""
        self.last_activity = time.time()
        if self.countdown_label and self.countdown_label.winfo_exists():
            self.countdown_label.config(text="")

    def check_inactivity(self):
        """Check for idle time and lock if needed"""
        if not self.is_locked:
            idle_time = time.time() - self.last_activity
            remaining_time = max(0, self.idle_timeout - idle_time)
            
            # Update countdown if in main app
            if hasattr(self, 'main_frame') and remaining_time < 60:  # Show last 60s
                if not self.countdown_label:
                    self.countdown_label = ttk.Label(self.main_frame, 
                                                text="",
                                                foreground="orange")
                    self.countdown_label.pack(side=tk.BOTTOM, pady=5)
                self.countdown_label.config(
                    text=f"Locking in {int(remaining_time)}s..."
                )
            
            # Lock if timeout reached
            if idle_time >= self.idle_timeout:
                self.lock_app()
        
        # Check every second
        self.lock_timer = self.root.after(1000, self.check_inactivity)
        
    def lock_app(self):
        """Lock the application"""
        if not self.is_locked:
            self.is_locked = True
            self.clear_window()
            
            # Show lock screen
            frame = ttk.Frame(self.root, padding="30 30 30 30")
            frame.pack(expand=True, fill=tk.BOTH)
            
            ttk.Label(frame, 
                    text="Session Locked", 
                    font=('Helvetica', 16, 'bold')).pack(pady=10)
            
            ttk.Label(frame, 
                    text="Enter Master Password to Unlock").pack(pady=5)
            
            self.unlock_entry = ttk.Entry(frame, show="•", width=30)
            self.unlock_entry.pack(pady=10)
            
            ttk.Button(frame, 
                    text="Unlock", 
                    command=self.unlock_app).pack(pady=20)
            
            # Bind Enter key to unlock
            self.root.bind('<Return>', lambda e: self.unlock_app())
            
            # Clear any countdown
            if self.countdown_label:
                self.countdown_label.config(text="")

    def unlock_app(self):
        """Unlock the application"""
        password = self.unlock_entry.get()
        if self.pm.verify_master_password(password):
            self.is_locked = False
            self.reset_inactivity_timer()
            self.show_main_app()
        else:
            messagebox.showerror("Error", "Incorrect password")
            
    def check_password_strength(self, password):
        """Rate password strength (0-4)"""
        if len(password) < 8:
            return 0  # Weak
        
        score = 1  # Basic
        if any(c.isupper() for c in password):
            score += 1  # +1 for uppercase
        if any(c.isdigit() for c in password):
            score += 1  # +1 for digits
        if any(c in string.punctuation for c in password):
            score += 1  # +1 for symbols
        
        return min(score, 4)  # Cap at 4 (Strong)
    
    
    def is_master_password_set(self):
        cursor = self.pm.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM master_password')
        return cursor.fetchone()[0] > 0
    
    def show_set_master_password(self):
        """Show the set master password screen"""
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
        pw1 = self.master_pw1.get()
        pw2 = self.master_pw2.get()
        
        if not pw1 or not pw2:
            messagebox.showerror("Error", "Password cannot be empty")
            return
        
        if pw1 != pw2:
            messagebox.showerror("Error", "Passwords don't match")
            return
        
        self.pm.set_master_password(pw1)
        messagebox.showinfo("Success", "Master password set successfully")
        self.show_main_app()
    
    def show_login(self):
        """Show the login screen"""
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
        password = self.master_pw_entry.get()
        if self.pm.verify_master_password(password):
            self.show_main_app()
        else:
            messagebox.showerror("Error", "Incorrect master password")
    
    def show_main_app(self):
        """Show the main application interface"""
        self.clear_window()
        self.is_locked = False
        self.reset_inactivity_timer()

        # Create main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Create countdown label
        self.countdown_label = ttk.Label(self.main_frame, text="", foreground="orange")
        self.countdown_label.pack(side=tk.BOTTOM, pady=5)

        # Create sidebar
        self.sidebar = ttk.Frame(self.main_frame, width=200, style='TFrame')
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 10))
        
        # Sidebar buttons
        buttons = [
            ("Add Password", self.show_add_password),
            ("View Passwords", self.show_password_list),
            ("Generate Password", self.show_generate_password),
            ("Change Master", self.show_change_master),
            ("Import/Export", self.show_import_export),
            ("Emergency Access", self.show_emergency_access),
            ("Activity Log", self.show_activity_log),
            ("Auto-Lock Settings", self.show_lock_settings),
            ("Exit", self.exit_app)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(self.sidebar, text=text, command=command, style='TButton')
            btn.pack(fill=tk.X, pady=5)
        
        # Create main content area
        self.content = ttk.Frame(self.main_frame)
        self.content.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)
        
        # Show password list by default
        self.show_password_list()

    #REQUEST ACCESS
    def build_request_access_form(self, parent):
        """Form for emergency contacts to request access"""
        frame = ttk.Frame(parent, padding=20)
        frame.pack(expand=True, fill=tk.BOTH)
        
        ttk.Label(frame, 
                text="Emergency Access Request", 
                font=('Helvetica', 14, 'bold')).pack(pady=10)
        
        ttk.Label(frame, text="Your Email:").pack(pady=5)
        self.emergency_email = ttk.Entry(frame, width=30)
        self.emergency_email.pack(pady=5)
        
        ttk.Label(frame, text="Security Question:").pack(pady=5)
        self.emergency_question = ttk.Label(frame, text="", wraplength=300)
        self.emergency_question.pack(pady=5)
        
        ttk.Label(frame, text="Answer:").pack(pady=5)
        self.emergency_answer = ttk.Entry(frame, width=30)
        self.emergency_answer.pack(pady=5)
        
        ttk.Button(frame, 
                text="Look Up Question", 
                command=self.load_security_question).pack(pady=10)
        
        ttk.Button(frame, 
                text="Submit Request", 
                command=self.submit_emergency_request,
                style='Emergency.TButton').pack(pady=20)

    def load_security_question(self):
        """Load security question for the provided email"""
        email = self.emergency_email.get()
        cursor = self.pm.conn.cursor()
        cursor.execute('''
        SELECT secret_question FROM emergency_access 
        WHERE contact_email = ? AND status = 'approved'
        ''', (email,))
        result = cursor.fetchone()
        
        if result:
            self.emergency_question.config(text=result[0])
        else:
            messagebox.showerror("Error", "No approved emergency contact found with that email")

    def submit_emergency_request(self):
        """Process emergency access request"""
        if self.pm.emergency_access.request_access(
            self.emergency_email.get(),
            self.emergency_answer.get()
        ):
            messagebox.showinfo(
                "Request Submitted",
                "Access will be granted after the waiting period\n"
                "The account owner has been notified"
            )
        else:
            messagebox.showerror("Error", "Invalid credentials or contact not approved")
    
    # EMERGENCY ACCESS MANAGEMENT
    def show_emergency_access(self):
        """Main emergency access control panel"""
        self.clear_content()

        notebook = ttk.Notebook(self.content)
        notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Tab 1: Manage Contacts
        manage_frame = ttk.Frame(notebook)
        self.build_contacts_table(manage_frame)
        notebook.add(manage_frame, text="My Emergency Contacts")

        # Tab 2: Access Requests
        if self.check_pending_requests():
            requests_frame = ttk.Frame(notebook)
            self.build_requests_table(requests_frame)  # Correctly call build_requests_table
            notebook.add(requests_frame, text="Pending Requests")

        # Tab 3: Request Access (for emergency contacts)
        request_frame = ttk.Frame(notebook)
        self.build_request_access_form(request_frame)
        notebook.add(request_frame, text="Request Emergency Access")
        
    def build_contacts_table(self, parent):
        """Show configured emergency contacts"""
        columns = ('name', 'email', 'access', 'status', 'wait_period')
        self.contacts_tree = ttk.Treeview(parent, columns=columns, show='headings')

        # Configure columns
        self.contacts_tree.heading('name', text='Contact Name')
        self.contacts_tree.heading('email', text='Email')
        self.contacts_tree.heading('access', text='Access Level')
        self.contacts_tree.heading('status', text='Status')
        self.contacts_tree.heading('wait_period', text='Delay (hrs)')

        # Add data
        cursor = self.pm.conn.cursor()
        cursor.execute('SELECT contact_name, contact_email, access_level, status, wait_period FROM emergency_access')
        for row in cursor.fetchall():
            self.contacts_tree.insert('', tk.END, values=row)

        # Add controls
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, 
                text="Add Contact", 
                command=self.show_add_contact_dialog).pack(side=tk.LEFT)
        ttk.Button(btn_frame, 
                text="Remove Selected", 
                command=self.remove_contact).pack(side=tk.LEFT, padx=5)

        self.contacts_tree.pack(expand=True, fill=tk.BOTH)

    def build_requests_table(self, parent):
        """Show pending emergency access requests"""
        columns = ('name', 'email', 'request_date', 'wait_period', 'status')
        self.requests_tree = ttk.Treeview(parent, columns=columns, show='headings')

        # Configure columns
        self.requests_tree.heading('name', text='Contact Name')
        self.requests_tree.heading('email', text='Email')
        self.requests_tree.heading('request_date', text='Request Date')
        self.requests_tree.heading('wait_period', text='Wait Period (hrs)')
        self.requests_tree.heading('status', text='Status')

        # Add data
        cursor = self.pm.conn.cursor()
        cursor.execute('''
        SELECT contact_name, contact_email, request_date, wait_period, status 
        FROM emergency_access 
        WHERE status = 'pending'
        ''')
        for row in cursor.fetchall():
            self.requests_tree.insert('', tk.END, values=row)

        # Add controls
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(btn_frame, 
                text="Approve Selected", 
                command=self.approve_request).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, 
                text="Reject Selected", 
                command=self.reject_request).pack(side=tk.LEFT, padx=5)

        self.requests_tree.pack(expand=True, fill=tk.BOTH)
        
    def approve_request(self):
        """Approve the selected emergency access request"""
        selected_item = self.requests_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No request selected")
            return

        contact_email = self.requests_tree.item(selected_item, 'values')[1]  # Get the email of the selected contact
        confirm = messagebox.askyesno("Confirm Approval", f"Approve access request for {contact_email}?")
        if confirm:
            try:
                cursor = self.pm.conn.cursor()
                cursor.execute('''
                UPDATE emergency_access 
                SET status = 'approved', grant_date = ? 
                WHERE contact_email = ?
                ''', (datetime.now().isoformat(), contact_email))
                self.pm.conn.commit()
                self.show_emergency_access()  # Refresh the emergency access view
                messagebox.showinfo("Success", "Request approved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to approve request: {str(e)}")
                
    def reject_request(self):
        """Reject the selected emergency access request"""
        selected_item = self.requests_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No request selected")
            return

        contact_email = self.requests_tree.item(selected_item, 'values')[1]  # Get the email of the selected contact
        confirm = messagebox.askyesno("Confirm Rejection", f"Reject access request for {contact_email}?")
        if confirm:
            try:
                cursor = self.pm.conn.cursor()
                cursor.execute('''
                UPDATE emergency_access 
                SET status = 'rejected' 
                WHERE contact_email = ?
                ''', (contact_email,))
                self.pm.conn.commit()
                self.show_emergency_access()  # Refresh the emergency access view
                messagebox.showinfo("Success", "Request rejected successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to reject request: {str(e)}")
        
    #AUTOMATIC ACCESS GRANTING
    def check_pending_requests(self):
        """Check for requests that have completed wait period"""
        cursor = self.pm.conn.cursor()
        cursor.execute('''
        SELECT id, request_date, wait_period 
        FROM emergency_access 
        WHERE status = 'pending'
        ''')
        
        now = datetime.now()
        granted = False
        
        for contact_id, request_date, wait_period in cursor.fetchall():
            request_time = datetime.fromisoformat(request_date)
            if (now - request_time).total_seconds() >= wait_period * 3600:
                self.pm.emergency_access.grant_access(contact_id)
                granted = True
        
        return granted
        
    def remove_contact(self):
        """Remove the selected emergency contact"""
        selected_item = self.contacts_tree.selection()
        if not selected_item:
            messagebox.showwarning("Warning", "No contact selected")
            return

        contact_email = self.contacts_tree.item(selected_item, 'values')[1]  # Get the email of the selected contact
        confirm = messagebox.askyesno("Confirm Delete", f"Are you sure you want to remove the contact: {contact_email}?")
        if confirm:
            try:
                cursor = self.pm.conn.cursor()
                cursor.execute('DELETE FROM emergency_access WHERE contact_email = ?', (contact_email,))
                self.pm.conn.commit()
                self.show_emergency_access()  # Refresh the emergency access view
                messagebox.showinfo("Success", "Contact removed successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to remove contact: {str(e)}")

    def show_add_contact_dialog(self):
        """Dialog to add new emergency contact"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Emergency Contact")
        
        ttk.Label(dialog, text="Contact Name:").grid(row=0, column=0, sticky=tk.E, pady=5)
        name_entry = ttk.Entry(dialog, width=30)
        name_entry.grid(row=0, column=1, pady=5)
        
        ttk.Label(dialog, text="Email Address:").grid(row=1, column=0, sticky=tk.E, pady=5)
        email_entry = ttk.Entry(dialog, width=30)
        email_entry.grid(row=1, column=1, pady=5)
        
        ttk.Label(dialog, text="Access Level:").grid(row=2, column=0, sticky=tk.E, pady=5)
        access_combo = ttk.Combobox(dialog, values=["viewer", "full"], state="readonly")
        access_combo.grid(row=2, column=1, pady=5)
        access_combo.current(0)
        
        ttk.Label(dialog, text="Wait Period (hours):").grid(row=3, column=0, sticky=tk.E, pady=5)
        wait_spin = ttk.Spinbox(dialog, from_=1, to=168, width=5)  # 1hr to 1 week
        wait_spin.grid(row=3, column=1, pady=5)
        wait_spin.set("72")
        
        ttk.Label(dialog, text="Security Question:").grid(row=4, column=0, sticky=tk.E, pady=5)
        question_entry = ttk.Entry(dialog, width=30)
        question_entry.grid(row=4, column=1, pady=5)
        
        ttk.Label(dialog, text="Answer:").grid(row=5, column=0, sticky=tk.E, pady=5)
        answer_entry = ttk.Entry(dialog, width=30, show="•")
        answer_entry.grid(row=5, column=1, pady=5)
        
        def save_contact():
            self.pm.emergency_access.add_contact(
                name_entry.get(),
                email_entry.get(),
                access_combo.get(),
                int(wait_spin.get()),
                question_entry.get(),
                answer_entry.get()
            )
            dialog.destroy()
            self.show_emergency_access()  # Refresh view
        
        ttk.Button(dialog, text="Save", command=save_contact).grid(row=6, columnspan=2, pady=10)
        
    def show_activity_log(self):
        """Display the activity log"""
        self.clear_content()
        
        frame = ttk.Frame(self.content)
        frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Toolbar
        toolbar = ttk.Frame(frame)
        toolbar.pack(fill=tk.X, pady=5)
        
        ttk.Button(toolbar, 
                text="Export Log", 
                command=self.export_activity_log).pack(side=tk.LEFT)
        
        ttk.Button(toolbar, 
                text="Clear Log", 
                command=self.clear_activity_log).pack(side=tk.LEFT, padx=5)
        
        # Treeview for logs
        columns = ('timestamp', 'event_type', 'description', 'service')
        self.log_tree = ttk.Treeview(frame, columns=columns, show='headings')
        
        # Configure columns
        self.log_tree.heading('timestamp', text='Timestamp')
        self.log_tree.heading('event_type', text='Event Type')
        self.log_tree.heading('description', text='Description')
        self.log_tree.heading('service', text='Service')
        
        self.log_tree.column('timestamp', width=180, stretch=False)
        self.log_tree.column('event_type', width=120, stretch=False)
        self.log_tree.column('description', width=300)
        self.log_tree.column('service', width=150)
        
        # Add to the toolbar in show_activity_log()
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT, padx=5)

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.log_search_entry = ttk.Entry(search_frame, width=20)
        self.log_search_entry.pack(side=tk.LEFT, padx=5)
        self.log_search_entry.bind('<Return>', lambda e: self.load_activity_logs(self.log_search_entry.get()))
        ttk.Button(search_frame, text="🔍", command=lambda: self.load_activity_logs(self.log_search_entry.get())).pack(side=tk.LEFT)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_tree.pack(expand=True, fill=tk.BOTH)
        
        # Load logs
        self.load_activity_logs()

    def load_activity_logs(self, search_filter=None):
        """Populate the log viewer"""
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        
        cursor = self.pm.conn.cursor()
        if search_filter:
            cursor.execute('''
            SELECT timestamp, event_type, description, related_service 
            FROM activity_logs 
            WHERE event_type LIKE ? OR description LIKE ?
            ORDER BY timestamp DESC
            ''', (f'%{search_filter}%', f'%{search_filter}%'))
        else:
            cursor.execute('''
            SELECT timestamp, event_type, description, related_service 
            FROM activity_logs 
            ORDER BY timestamp DESC
            ''')
        
        for row in cursor.fetchall():
            self.log_tree.insert('', tk.END, values=row)

    def export_activity_log(self):
        """Export logs to CSV"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv")]
        )
        if file_path:
            cursor = self.pm.conn.cursor()
            cursor.execute('SELECT * FROM activity_logs ORDER BY timestamp DESC')
            
            import csv
            with open(file_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Timestamp', 'Event Type', 'Description', 'Service', 'IP'])
                writer.writerows(cursor.fetchall())
            
            messagebox.showinfo("Success", f"Logs exported to {file_path}")

    def clear_activity_log(self):
        """Clear all logs (with confirmation)"""
        if messagebox.askyesno(
            "Confirm Clear",
            "Permanently delete all activity logs?",
            icon='warning'
        ):
            cursor = self.pm.conn.cursor()
            cursor.execute('DELETE FROM activity_logs')
            self.pm.conn.commit()
            self.load_activity_logs()
        
    def exit_app(self):
        """Clean up before exiting"""
        if self.lock_timer:
            self.root.after_cancel(self.lock_timer)
        self.root.quit()
        
    def show_lock_settings(self):
        """Configure auto-lock timeout"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Auto-Lock Settings")
        
        ttk.Label(dialog, text="Lock after (minutes):").pack(pady=10)
        
        self.timeout_var = tk.IntVar(value=self.idle_timeout // 60)
        spinbox = ttk.Spinbox(dialog, 
                            from_=1, 
                            to=60, 
                            textvariable=self.timeout_var,
                            width=5)
        spinbox.pack(pady=5)
        
        def save_settings():
            self.idle_timeout = self.timeout_var.get() * 60
            self.reset_inactivity_timer()
            dialog.destroy()
        
        ttk.Button(dialog, text="Save", command=save_settings).pack(pady=10)
    
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
        
        self.strength_label = ttk.Label(frame, text="Strength: ")
        self.strength_label.grid(row=3, column=3, padx=5)
        
        self.password_entry.bind("<KeyRelease>", self.update_strength_meter)
        
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
        
    def update_strength_meter(self, event):
        password = self.password_entry.get()
        strength = self.check_password_strength(password)
        colors = ["red", "orange", "yellow", "lightgreen", "green"]
        self.strength_label.config(
            text=f"Strength: {strength}/4",
            foreground=colors[strength]
        )
    
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
    
    def search_passwords(self):
        """Search passwords by service name"""
        search_term = self.search_entry.get()
        self.load_passwords(search_term)
    
    def get_selected_password_id(self):
        """Get the selected password ID from the treeview"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No password selected")
            return None
        return int(selected[0])
    
    def view_password_details(self):
        """View details of the selected password"""
        password_id = self.get_selected_password_id()
        if password_id is None:
            return

        password_data = self.pm.get_password_by_id(password_id)
        if not password_data:
            messagebox.showerror("Error", "Password not found")
            return

        # Create a details window
        details_window = tk.Toplevel(self.root)
        details_window.title("Password Details")
        details_window.geometry("500x400")

        frame = ttk.Frame(details_window, padding="20 20 20 20")
        frame.pack(expand=True, fill=tk.BOTH)

        ttk.Label(frame, text="Password Details", font=('Helvetica', 14, 'bold')).pack(pady=10)

        # Display fields
        fields = [
            ("Service:", password_data[1]),
            ("Username:", password_data[2] or "N/A"),
            ("Password:", "••••••••"),
            ("URL:", password_data[4] or "N/A"),
            ("Notes:", password_data[5] or "N/A"),
            ("Created:", password_data[6]),
            ("Last Updated:", password_data[7])
        ]

        for label, value in fields:
            field_frame = ttk.Frame(frame)
            field_frame.pack(fill=tk.X, pady=2)
            ttk.Label(field_frame, text=label, font=('Helvetica', 10, 'bold')).pack(side=tk.LEFT)
            if label == "Password:":
                ttk.Label(field_frame, text=value).pack(side=tk.LEFT, padx=5)
                ttk.Button(field_frame, text="Reveal",
                        command=lambda p=password_data[3]: self.reveal_password(p, field_frame)).pack(side=tk.LEFT, padx=5)
                ttk.Button(field_frame, text="Copy",
                        command=lambda p=password_data[3]: self.copy_decrypted_password(p)).pack(side=tk.LEFT, padx=5)
            else:
                ttk.Label(field_frame, text=value).pack(side=tk.LEFT)

        # Close button
        ttk.Button(frame, text="Close", command=details_window.destroy).pack(pady=20)
    
    def reveal_password(self, encrypted_password, frame):
        """Reveal the decrypted password"""
        decrypted = self.pm.decrypt(encrypted_password)
        for widget in frame.winfo_children():
            widget.destroy()
        ttk.Label(frame, text=decrypted).pack(side=tk.LEFT)
    
    def copy_decrypted_password(self, encrypted_password):
        """Copy decrypted password to clipboard"""
        decrypted = self.pm.decrypt(encrypted_password)
        pyperclip.copy(decrypted)
        messagebox.showinfo("Copied", "Password copied to clipboard")
    
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
                    
                    self.update_strength_meter(None)
                elif hasattr(self, 'edit_password'):
                    self.edit_password.delete(0, tk.END)
                    self.edit_password.insert(0, password)
                    
                    self.update_strength_meter(None)
                
                window.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Couldn't use password: {str(e)}")
    
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
    
    def export_passwords(self):
        """Export passwords to a file"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Export passwords to file"
        )
        
        if file_path:
            try:
                self.pm.export_passwords(file_path)
                messagebox.showinfo("Success", f"Passwords exported to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export passwords: {str(e)}")
    
    def import_passwords(self):
        """Import passwords from a file"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Select password file to import"
        )
        
        if file_path:
            confirm = messagebox.askyesno("Confirm Import", 
                                       "This will add all passwords from the file to your database. Continue?")
            if confirm:
                try:
                    imported = self.pm.import_passwords(file_path)
                    messagebox.showinfo("Success", f"Imported {imported} passwords successfully")
                    self.load_passwords()
                except Exception as e:
                    messagebox.showerror("Error", f"Failed to import passwords: {str(e)}")
    
    def clear_window(self):
        """Clear all widgets from the window"""
        for widget in self.root.winfo_children():
            widget.destroy()
        self.countdown_label = None  # Reset countdown_label
    
    def clear_content(self):
        """Clear the content area"""
        for widget in self.content.winfo_children():
            widget.destroy()

class PasswordManager:
    def __init__(self):
        # Get the path to the user's Documents folder
        documents_folder = Path.home() / "Documents" / "PasswordManager"
        documents_folder.mkdir(parents=True, exist_ok=True)  # Create the folder if it doesn't exist

        # Set paths for the database and encryption key
        self.db_path = documents_folder / "passwords.db"
        self.key_path = documents_folder / "encryption.key"

        self.key = None
        self.cipher_suite = None
        self.conn = None

        self.create_database()  # Initialize the database
        self.setup_encryption()  # Set up encryption
        self.logger = ActivityLogger(self.conn)  # Initialize the activity logger
        self.emergency_access = EmergencyAccess(self.conn, self)  # Initialize the emergency access

    def create_database(self):
        """Create the database and required tables if they don't exist"""
        self.conn = sqlite3.connect(self.db_path)  # Connect to the SQLite database
        cursor = self.conn.cursor()

        # Create the `master_password` table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS master_password (
            id INTEGER PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL
        )
        ''')

        # Create the `passwords` table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY,
            service TEXT NOT NULL,
            username TEXT,
            password TEXT NOT NULL,
            url TEXT,
            notes TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        ''')

        # Create the `activity_logs` table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT,
            related_service TEXT
        )
        ''')

        # Emergency contacts table
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS emergency_access (
            id INTEGER PRIMARY KEY,
            contact_name TEXT NOT NULL,
            contact_email TEXT NOT NULL UNIQUE,
            access_level TEXT CHECK(access_level IN ('viewer', 'full')),
            request_date TEXT,
            grant_date TEXT,
            status TEXT CHECK(status IN ('pending', 'approved', 'activated')),
            wait_period INTEGER DEFAULT 72,
            secret_question TEXT,
            secret_answer_hash TEXT
        )
        ''')

        # Emergency access logs
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS emergency_logs (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            contact_id INTEGER,
            action TEXT NOT NULL,
            FOREIGN KEY(contact_id) REFERENCES emergency_access(id)
        )
        ''')

        self.conn.commit()  # Save changes to the database

    def setup_encryption(self):
        """Setup encryption key or load existing one"""
        if self.key_path.exists():
            with open(self.key_path, 'rb') as f:
                self.key = f.read()
        else:
            self.key = Fernet.generate_key()
            with open(self.key_path, 'wb') as f:
                f.write(self.key)
        self.cipher_suite = Fernet(self.key)
    
    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hashed.hex(), salt
    
    def set_master_password(self, password):
        """Set the master password for the first time"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM master_password')
        if cursor.fetchone()[0] > 0:
            raise Exception("Master password already set")
        
        hashed, salt = self.hash_password(password)
        cursor.execute('INSERT INTO master_password (password_hash, salt) VALUES (?, ?)', 
                      (hashed, salt))
        self.conn.commit()
    
    def verify_master_password(self, password):
        """Verify the master password"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT password_hash, salt FROM master_password LIMIT 1')
        result = cursor.fetchone()
        if not result:
            raise Exception("No master password set")
        
        stored_hash, salt = result
        hashed, _ = self.hash_password(password, salt)
        success = hashed == stored_hash
        
        if success:
            self.logger.log_event("LOGIN_SUCCESS", "User logged in")
        else:
            self.logger.log_event("LOGIN_FAILED", "Failed login attempt")
        return success
    
    def encrypt(self, data):
        """Encrypt data"""
        return self.cipher_suite.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted_data):
        """Decrypt data"""
        return self.cipher_suite.decrypt(encrypted_data.encode()).decode()
    
    def generate_password(self, length=16, use_upper=True, use_digits=True, use_special=True):
        """Generate a strong random password"""
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
        self.logger.log_event("PASSWORD_ADD", f"Added password for {service}", service)
        """Add a new password entry"""
        encrypted_password = self.encrypt(password)
        now = datetime.now().isoformat()
        
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO passwords (service, username, password, url, notes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (service, username, encrypted_password, url, notes, now, now))
        self.conn.commit()
        return cursor.lastrowid
    
    def get_password_by_id(self, password_id):
        """Get password entry by ID"""
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT id, service, username, password, url, notes, created_at, updated_at 
        FROM passwords WHERE id = ?
        ''', (password_id,))
        return cursor.fetchone()
    
    def update_password(self, password_id, service, username, password, url=None, notes=None):
        """Update an existing password entry"""
        encrypted_password = self.encrypt(password)
        updated_at = datetime.now().isoformat()
        
        cursor = self.conn.cursor()
        cursor.execute('''
        UPDATE passwords 
        SET service = ?, username = ?, password = ?, url = ?, notes = ?, updated_at = ?
        WHERE id = ?
        ''', (service, username, encrypted_password, url, notes, updated_at, password_id))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def delete_password(self, password_id):
        password_data = self.get_password_by_id(password_id)
        if password_data:
            self.logger.log_event(
                "PASSWORD_DELETE", 
                f"Deleted password for {password_data[1]}", 
                password_data[1]
            )
        """Delete a password entry"""
        cursor = self.conn.cursor()
        cursor.execute('DELETE FROM passwords WHERE id = ?', (password_id,))
        self.conn.commit()
        return cursor.rowcount > 0
    
    def change_master_password(self, current_password, new_password):
        self.logger.log_event("PASSWORD_CHANGE", "Master password changed")
        """Change the master password"""
        if not self.verify_master_password(current_password):
            raise Exception("Current password is incorrect")
        
        hashed, salt = self.hash_password(new_password)
        cursor = self.conn.cursor()
        cursor.execute('UPDATE master_password SET password_hash = ?, salt = ?', 
                      (hashed, salt))
        self.conn.commit()
    
    def export_passwords(self, file_path):
        """Export passwords to a file"""
        cursor = self.conn.cursor()
        cursor.execute('SELECT service, username, password, url, notes FROM passwords')
        passwords = cursor.fetchall()
        
        with open(file_path, 'w') as f:
            f.write("Password Manager Export\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for service, username, encrypted_password, url, notes in passwords:
                decrypted_password = self.decrypt(encrypted_password)
                f.write(f"Service: {service}\n")
                f.write(f"Username: {username or 'N/A'}\n")
                f.write(f"Password: {decrypted_password}\n")
                f.write(f"URL: {url or 'N/A'}\n")
                f.write(f"Notes: {notes or 'N/A'}\n")
                f.write("-" * 40 + "\n")
    
    def import_passwords(self, file_path):
        """Import passwords from an exported file"""
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        # Simple parser for the export format
        entries = []
        current_entry = {}
        
        for line in lines:
            line = line.strip()
            if line.startswith("Service: "):
                current_entry['service'] = line[9:]
            elif line.startswith("Username: "):
                current_entry['username'] = line[10:] if line[10:] != 'N/A' else None
            elif line.startswith("Password: "):
                current_entry['password'] = line[10:]
            elif line.startswith("URL: "):
                current_entry['url'] = line[5:] if line[5:] != 'N/A' else None
            elif line.startswith("Notes: "):
                current_entry['notes'] = line[7:] if line[7:] != 'N/A' else None
            elif line.startswith("-" * 40):
                if current_entry:
                    entries.append(current_entry)
                    current_entry = {}
        
        if not entries:
            raise Exception("No valid password entries found in the file")
        
        imported_count = 0
        cursor = self.conn.cursor()
        now = datetime.now().isoformat()
        
        for entry in entries:
            try:
                encrypted_password = self.encrypt(entry['password'])
                cursor.execute('''
                INSERT INTO passwords (service, username, password, url, notes, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    entry['service'],
                    entry.get('username'),
                    encrypted_password,
                    entry.get('url'),
                    entry.get('notes'),
                    now,
                    now
                ))
                imported_count += 1
            except Exception as e:
                print(f"Error importing entry for {entry.get('service')}: {e}")
        
        self.conn.commit()
        return imported_count

    
    
class ActivityLogger:
    def __init__(self, conn):
        self.conn = conn
    
    def log_event(self, event_type, description="", service=None):
        """Log security events with automatic timestamp"""
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO activity_logs 
        (timestamp, event_type, description, related_service)
        VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            event_type,
            description,
            service
        ))
        self.conn.commit()
        
class EmergencyAccess:
    def __init__(self, conn, password_manager):
        self.conn = conn
        self.password_manager = password_manager
        
    def add_contact(self, name, email, access_level, wait_period, question, answer):
        """Add a new emergency contact"""
        hashed_answer, salt = self.password_manager.hash_password(answer)
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO emergency_access 
        (contact_name, contact_email, access_level, wait_period, 
         secret_question, secret_answer_hash, request_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (name, email, access_level, wait_period, 
              question, hashed_answer, 
              datetime.now().isoformat(), 'pending'))
        self.conn.commit()
        
    def request_access(self, email, answer):
        """Initiate emergency access request"""
        cursor = self.conn.cursor()
        cursor.execute('''
        SELECT id, secret_answer_hash, wait_period 
        FROM emergency_access 
        WHERE contact_email = ? AND status = 'approved'
        ''', (email,))
        contact = cursor.fetchone()
        
        if not contact:
            return False
            
        contact_id, correct_hash, wait_period = contact
        if not self.verify_password(answer, correct_hash):
            return False
            
        # Update request
        cursor.execute('''
        UPDATE emergency_access 
        SET request_date = ?, status = 'pending'
        WHERE id = ?
        ''', (datetime.now().isoformat(), contact_id))
        self.conn.commit()
        
        # Log the request
        self.log_action(contact_id, "ACCESS_REQUESTED")
        return True
    
    def grant_access(self, contact_id):
        """Approve access after wait period"""
        cursor = self.conn.cursor()
        cursor.execute('''
        UPDATE emergency_access 
        SET grant_date = ?, status = 'activated'
        WHERE id = ?
        ''', (datetime.now().isoformat(), contact_id))
        self.conn.commit()
        self.log_action(contact_id, "ACCESS_GRANTED")
    
    def log_action(self, contact_id, action):
        """Record emergency access events"""
        cursor = self.conn.cursor()
        cursor.execute('''
        INSERT INTO emergency_logs (timestamp, contact_id, action)
        VALUES (?, ?, ?)
        ''', (datetime.now().isoformat(), contact_id, action))
        self.conn.commit()
        
if __name__ == "__main__":
    try:
        on_program_start()
        program_running()
        atexit.register(on_program_exit)
        root = tk.Tk()
        app = PasswordManagerGUI(root)
        root.mainloop()
    except KeyboardInterrupt:
        print("\nProgram interrupted by user. Exiting...")