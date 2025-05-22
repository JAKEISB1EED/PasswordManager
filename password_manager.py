import tkinter as tk
from tkinter import messagebox, filedialog
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import mysql.connector
import base64
import hashlib
import string
import secrets
from datetime import datetime, timedelta
import os
import pyotp
import qrcode
from PIL import Image, ImageTk


class AdvancedPasswordManager:
    def __init__(self):
        self.root = ttk.Window(themename="darkly")
        self.root.title("Advanced Password Manager")
        self.root.geometry("1000x700")

        # Initialize database
        self.setup_database()

        # Check database setup
        self.check_database_setup()

        # Initialize storage
        self.passwords = {}
        self.master_password_hash = None
        self.encryption_key = None
        self.two_factor_secret = None

        # Show the initial screen
        self.show_initial_screen()

    def setup_database(self):
        try:
            self.conn = mysql.connector.connect(
                host="localhost",
                user="root",
                password="root",
                database="password_manager"
            )
            self.cursor = self.conn.cursor(buffered=True)

            # Create tables
            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INT PRIMARY KEY,
                master_password_hash VARCHAR(255),
                two_factor_secret VARCHAR(32)
            )
            ''')

            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INT AUTO_INCREMENT PRIMARY KEY,
                service VARCHAR(255) NOT NULL,
                username VARCHAR(255) NOT NULL,
                encrypted_password TEXT NOT NULL,
                category VARCHAR(50),
                tags TEXT,
                created_date DATETIME,
                expiry_date DATETIME,
                last_modified DATETIME
            )
            ''')

            self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS secure_notes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                encrypted_content TEXT NOT NULL,
                category VARCHAR(50),
                created_date DATETIME,
                last_modified DATETIME
            )
            ''')

            self.conn.commit()
        except mysql.connector.Error as e:
            messagebox.showerror("Database Error", f"Failed to setup database: {str(e)}")

    def is_master_password_set(self):
        try:
            self.cursor.execute("SELECT master_password_hash FROM users WHERE id = 1")
            result = self.cursor.fetchone()
            return result is not None and result[0] is not None
        except mysql.connector.Error:
            return False

    def show_initial_screen(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame,
            text="Advanced Password Manager",
            font=('Helvetica', 24, "bold")
        ).pack(pady=20)

        if self.is_master_password_set():
            ttk.Button(
                frame,
                text="Login",
                command=self.show_login_screen,
                style="success.TButton",
                width=20
            ).pack(pady=10)
        else:
            ttk.Label(
                frame,
                text="No master password set. Please set up your master password.",
                font=('Helvetica', 12)
            ).pack(pady=10)

        ttk.Button(
            frame,
            text="Set/Change Master Password",
            command=self.show_setup_screen,
            style="info.TButton",
            width=25
        ).pack(pady=10)

    def show_setup_screen(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame,
            text="Set Up Master Password",
            font=('Helvetica', 20, "bold")
        ).pack(pady=20)

        ttk.Label(frame, text="Enter New Master Password:", font=("Helvetica", 12)).pack(pady=5)
        password_entry = ttk.Entry(frame, show="●", font=("Helvetica", 12), width=30)
        password_entry.pack(pady=5)

        ttk.Label(frame, text="Confirm Master Password:", font=("Helvetica", 12)).pack(pady=5)
        confirm_entry = ttk.Entry(frame, show="●", font=("Helvetica", 12), width=30)
        confirm_entry.pack(pady=5)

        def save_master_password():
            password = password_entry.get()
            confirm = confirm_entry.get()

            if not password:
                messagebox.showerror("Error", "Password cannot be empty!")
                return

            if len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters long!")
                return

            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match!")
                return

            # Save the master password hash and set encryption key
            self.master_password_hash = hashlib.sha256(password.encode()).hexdigest()
            self.encryption_key = password

            # Generate 2FA secret
            self.two_factor_secret = pyotp.random_base32()

            try:
                self.cursor.execute('''
                INSERT INTO users (id, master_password_hash, two_factor_secret)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE 
                    master_password_hash = VALUES(master_password_hash),
                    two_factor_secret = VALUES(two_factor_secret)
                ''', (1, self.master_password_hash, self.two_factor_secret))
                self.conn.commit()
            except mysql.connector.Error as e:
                messagebox.showerror("Database Error", f"Failed to save master password: {str(e)}")
                return

            messagebox.showinfo("Success", "Master password set successfully!")
            self.show_2fa_setup()

        ttk.Button(
            frame,
            text="Set Master Password",
            command=save_master_password,
            style="success.TButton",
            width=20
        ).pack(pady=20)

        ttk.Button(
            frame,
            text="Back",
            command=self.show_initial_screen,
            style="secondary.TButton",
            width=20
        ).pack(pady=10)

    def show_2fa_setup(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame,
            text="Set Up Two-Factor Authentication",
            font=('Helvetica', 20, "bold")
        ).pack(pady=20)

        ttk.Label(
            frame,
            text="1. Install an authenticator app (e.g., Google Authenticator, Microsoft Authenticator, or Authy)",
            font=('Helvetica', 12)
        ).pack(pady=5, anchor="w")

        ttk.Label(
            frame,
            text="2. Scan the QR code below with your authenticator app:",
            font=('Helvetica', 12)
        ).pack(pady=5, anchor="w")

        # Generate QR code
        totp = pyotp.TOTP(self.two_factor_secret)
        uri = totp.provisioning_uri("AdvancedPasswordManager", issuer_name="YourApp")
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        qr_image = qr.make_image(fill_color="black", back_color="white")
        qr_image.save("qr_code.png")

        # Display QR code
        qr_image = Image.open("qr_code.png")
        qr_photo = ImageTk.PhotoImage(qr_image)
        qr_label = ttk.Label(frame, image=qr_photo)
        qr_label.image = qr_photo  # Keep a reference
        qr_label.pack(pady=10)

        ttk.Label(
            frame,
            text="3. If you can't scan the QR code, use this secret key in your app:",
            font=("Helvetica", 12)
        ).pack(pady=5, anchor="w")
        ttk.Label(frame, text=self.two_factor_secret, font=("Helvetica", 14, "bold")).pack(pady=5)

        ttk.Label(
            frame,
            text="4. Enter the 6-digit code from your authenticator app:",
            font=("Helvetica", 12)
        ).pack(pady=5, anchor="w")
        code_entry = ttk.Entry(frame, font=("Helvetica", 12), width=10)
        code_entry.pack(pady=5)

        def verify_2fa():
            entered_code = code_entry.get()
            if totp.verify(entered_code):
                messagebox.showinfo("Success", "Two-factor authentication set up successfully!")
                self.show_initial_screen()
            else:
                messagebox.showerror("Error", "Invalid code. Please try again.")

        ttk.Button(
            frame,
            text="Verify and Complete Setup",
            command=verify_2fa,
            style="success.TButton",
            width=25
        ).pack(pady=20)

        ttk.Button(
            frame,
            text="Cancel",
            command=self.show_initial_screen,
            style="secondary.TButton",
            width=25
        ).pack(pady=10)

        # Clean up temporary QR code file
        os.remove("qr_code.png")

    def show_login_screen(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame,
            text="Login to Password Manager",
            font=('Helvetica', 20, "bold")
        ).pack(pady=20)

        ttk.Label(frame, text="Enter Master Password:", font=("Helvetica", 12)).pack(pady=5)
        password_entry = ttk.Entry(frame, show="●", font=("Helvetica", 12), width=30)
        password_entry.pack(pady=5)

        def verify_password():
            password = password_entry.get()
            hashed_password = hashlib.sha256(password.encode()).hexdigest()

            try:
                self.cursor.execute("SELECT master_password_hash, two_factor_secret FROM users WHERE id = 1")
                result = self.cursor.fetchone()

                if result and hashed_password == result[0]:
                    self.master_password_hash = result[0]
                    self.encryption_key = password
                    self.two_factor_secret = result[1]
                    messagebox.showinfo("Debug", f"2FA Secret: {self.two_factor_secret[:5]}...")
                    self.show_2fa_verification()
                else:
                    messagebox.showerror("Error", "Incorrect master password!")
            except mysql.connector.Error as e:
                messagebox.showerror("Database Error", f"Failed to retrieve user data: {str(e)}")

        ttk.Button(
            frame,
            text="Login",
            command=verify_password,
            style="success.TButton",
            width=20
        ).pack(pady=20)

        ttk.Button(
            frame,
            text="Back",
            command=self.show_initial_screen,
            style="secondary.TButton",
            width=20
        ).pack(pady=10)

    def show_2fa_verification(self):
        self.clear_window()

        frame = ttk.Frame(self.root, padding="20")
        frame.pack(expand=True, fill="both")

        ttk.Label(
            frame,
            text="Two-Factor Authentication",
            font=('Helvetica', 20, "bold")
        ).pack(pady=20)

        ttk.Label(frame, text="Enter the 6-digit code from your authenticator app:", font=("Helvetica", 12)).pack(
            pady=5)
        code_entry = ttk.Entry(frame, font=("Helvetica", 12), width=10)
        code_entry.pack(pady=5)

        def verify_2fa():
            entered_code = code_entry.get()
            totp = pyotp.TOTP(self.two_factor_secret)
            if totp.verify(entered_code):
                self.setup_gui()
            else:
                messagebox.showerror("Error",
                                     f"Invalid code. Please try again. Debug: Secret: {self.two_factor_secret[:5]}...")

        ttk.Button(
            frame,
            text="Verify",
            command=verify_2fa,
            style="success.TButton",
            width=20
        ).pack(pady=20)

        ttk.Label(frame, text=f"Debug: 2FA Secret: {self.two_factor_secret[:5]}...", font=("Helvetica", 10)).pack(
            pady=5)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def setup_gui(self):
        self.clear_window()

        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)

        # Create main tabs
        self.passwords_tab = ttk.Frame(self.notebook)
        self.generator_tab = ttk.Frame(self.notebook)
        self.secure_notes_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)

        # Add tabs to notebook
        self.notebook.add(self.passwords_tab, text='Passwords')
        self.notebook.add(self.generator_tab, text='Generator')
        self.notebook.add(self.secure_notes_tab, text='Secure Notes')
        self.notebook.add(self.settings_tab, text='Settings')

        # Setup each tab
        self.setup_passwords_tab()
        self.setup_generator_tab()
        self.setup_secure_notes_tab()
        self.setup_settings_tab()

    def setup_passwords_tab(self):
        # Search frame
        search_frame = ttk.Frame(self.passwords_tab)
        search_frame.pack(fill='x', padx=10, pady=10)

        ttk.Label(search_frame, text="Search:", font=("Helvetica", 12)).pack(side='left')
        self.search_var = tk.StringVar()
        ttk.Entry(search_frame, textvariable=self.search_var, font=("Helvetica", 12), width=30).pack(side='left',
                                                                                                     padx=5)
        ttk.Button(search_frame, text="Search", command=self.search_passwords, style="primary.TButton").pack(
            side='left', padx=5)

        # Category filter
        ttk.Label(search_frame, text="Category:", font=("Helvetica", 12)).pack(side='left', padx=5)
        self.category_var = tk.StringVar(value="All")
        categories = ["All", "Personal", "Work", "Finance", "Social"]
        category_combo = ttk.Combobox(search_frame, textvariable=self.category_var, values=categories,
                                      font=("Helvetica", 12), width=15)
        category_combo.pack(side='left')
        category_combo.bind("<<ComboboxSelected>>", lambda e: self.search_passwords())

        # Buttons frame
        button_frame = ttk.Frame(self.passwords_tab)
        button_frame.pack(fill='x', padx=10, pady=10)

        ttk.Button(button_frame, text="Add Password", command=self.add_password_dialog, style="success.TButton").pack(
            side='left', padx=5)
        ttk.Button(button_frame, text="Edit Selected", command=self.edit_password, style="info.TButton").pack(
            side='left', padx=5)
        ttk.Button(button_frame, text="Delete Selected", command=self.delete_password, style="danger.TButton").pack(
            side='left', padx=5)

        # Password list
        columns = ("Service", "Username", "Category", "Modified", "Expiry")
        self.password_tree = ttk.Treeview(self.passwords_tab, columns=columns, show="headings")

        # Configure columns
        for col in columns:
            self.password_tree.heading(col, text=col)
            self.password_tree.column(col, width=150)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(self.passwords_tab, orient="vertical", command=self.password_tree.yview)
        self.password_tree.configure(yscrollcommand=scrollbar.set)

        # Pack elements
        self.password_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y')

        # Load passwords
        self.update_password_list()

    def setup_generator_tab(self):
        frame = ttk.Frame(self.generator_tab, padding="20")
        frame.pack(fill='both', expand=True)

        # Length control
        ttk.Label(frame, text="Password Length:", font=("Helvetica", 12)).grid(row=0, column=0, sticky='w', pady=5)
        self.length_var = tk.StringVar(value="16")
        length_spin = ttk.Spinbox(frame, from_=8, to=64, textvariable=self.length_var, width=5, font=("Helvetica", 12))
        length_spin.grid(row=0, column=1, sticky='w', pady=5)

        # Character type options
        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_digits = tk.BooleanVar(value=True)
        self.use_special = tk.BooleanVar(value=True)

        ttk.Checkbutton(frame, text="Uppercase (A-Z)", variable=self.use_uppercase).grid(row=1, column=0, columnspan=2,
                                                                                         sticky='w')
        ttk.Checkbutton(frame, text="Lowercase (a-z)", variable=self.use_lowercase).grid(row=2, column=0, columnspan=2,
                                                                                         sticky='w')
        ttk.Checkbutton(frame, text="Digits (0-9)", variable=self.use_digits).grid(row=3, column=0, columnspan=2,
                                                                                   sticky='w')
        ttk.Checkbutton(frame, text="Special (!@#$)", variable=self.use_special).grid(row=4, column=0, columnspan=2,
                                                                                      sticky='w')

        # Generated password display
        ttk.Label(frame, text="Generated Password:", font=("Helvetica", 12)).grid(row=5, column=0, columnspan=2,
                                                                                  sticky='w', pady=(20, 5))
        self.generated_password = tk.StringVar()
        password_entry = ttk.Entry(frame, textvariable=self.generated_password, width=40, font=("Helvetica", 12))
        password_entry.grid(row=6, column=0, columnspan=2, sticky='w')

        # Buttons
        button_frame = ttk.Frame(frame)
        button_frame.grid(row=7, column=0, columnspan=2, pady=20)

        ttk.Button(button_frame, text="Generate", command=self.generate_password, style="success.TButton").pack(
            side='left', padx=5)
        ttk.Button(button_frame, text="Copy to Clipboard", command=self.copy_to_clipboard, style="info.TButton").pack(
            side='left', padx=5)

    def setup_secure_notes_tab(self):
        # Buttons frame
        button_frame = ttk.Frame(self.secure_notes_tab)
        button_frame.pack(fill='x', padx=10, pady=10)

        ttk.Button(button_frame, text="Add Note", command=self.add_note, style="success.TButton").pack(side='left',
                                                                                                       padx=5)
        ttk.Button(button_frame, text="Edit Note", command=self.edit_note, style="info.TButton").pack(side='left',
                                                                                                      padx=5)
        ttk.Button(button_frame, text="Delete Note", command=self.delete_note, style="danger.TButton").pack(side='left',
                                                                                                            padx=5)

        # Notes list
        columns = ("Title", "Category", "Modified")
        self.notes_tree = ttk.Treeview(self.secure_notes_tab, columns=columns, show="headings")

        for col in columns:
            self.notes_tree.heading(col, text=col)
            self.notes_tree.column(col, width=150)

        scrollbar = ttk.Scrollbar(self.secure_notes_tab, orient="vertical", command=self.notes_tree.yview)
        self.notes_tree.configure(yscrollcommand=scrollbar.set)

        self.notes_tree.pack(side='left', fill='both', expand=True, padx=10, pady=10)
        scrollbar.pack(side='right', fill='y')

        # Load notes
        self.update_notes_list()

    def setup_settings_tab(self):
        frame = ttk.Frame(self.settings_tab, padding="20")
        frame.pack(fill='both', expand=True)

        # Change master password button
        ttk.Button(frame, text="Change Master Password", command=self.change_master_password,
                   style="info.TButton").grid(row=0, column=0, columnspan=2, pady=5)

        # Backup/Restore buttons
        ttk.Button(frame, text="Backup Database", command=self.backup_database, style="success.TButton").grid(row=1,
                                                                                                              column=0,
                                                                                                              pady=20)
        ttk.Button(frame, text="Restore Database", command=self.restore_database, style="warning.TButton").grid(row=1,
                                                                                                                column=1,
                                                                                                                pady=20)

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            chars = ''

            if self.use_uppercase.get():
                chars += string.ascii_uppercase
            if self.use_lowercase.get():
                chars += string.ascii_lowercase
            if self.use_digits.get():
                chars += string.digits
            if self.use_special.get():
                chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

            if not chars:
                messagebox.showerror("Error", "Please select at least one character type!")
                return

            password = ''.join(secrets.choice(chars) for _ in range(length))
            self.generated_password.set(password)

        except ValueError:
            messagebox.showerror("Error", "Invalid password length!")

    def copy_to_clipboard(self):
        password = self.generated_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password generated yet!")

    def add_password_dialog(self):
        dialog = ttk.Toplevel(self.root)
        dialog.title("Add Password")
        dialog.geometry("400x300")

        # Form fields
        ttk.Label(dialog, text="Service:", font=("Helvetica", 12)).pack(pady=5)
        service_entry = ttk.Entry(dialog, font=("Helvetica", 12))
        service_entry.pack(pady=5)

        ttk.Label(dialog, text="Username:", font=("Helvetica", 12)).pack(pady=5)
        username_entry = ttk.Entry(dialog, font=("Helvetica", 12))
        username_entry.pack(pady=5)

        ttk.Label(dialog, text="Password:", font=("Helvetica", 12)).pack(pady=5)
        password_entry = ttk.Entry(dialog, show="●", font=("Helvetica", 12))
        password_entry.pack(pady=5)

        ttk.Label(dialog, text="Category:", font=("Helvetica", 12)).pack(pady=5)
        category_var = tk.StringVar(value="Personal")
        category_combo = ttk.Combobox(dialog, textvariable=category_var,
                                      values=["Personal", "Work", "Finance", "Social"], font=("Helvetica", 12))
        category_combo.pack(pady=5)

        def save():
            service = service_entry.get()
            username = username_entry.get()
            password = password_entry.get()
            category = category_var.get()

            if not all([service, username, password]):
                messagebox.showerror("Error", "All fields are required!")
                return

            try:
                # Save to database
                now = datetime.now().isoformat()
                expiry = (datetime.now() + timedelta(days=90)).isoformat()

                self.cursor.execute('''
                INSERT INTO passwords (service, username, encrypted_password, category, created_date, expiry_date, last_modified)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ''', (service, username, self.encrypt(password), category, now, expiry, now))

                self.conn.commit()
                self.update_password_list()
                dialog.destroy()
                messagebox.showinfo("Success", "Password saved successfully!")

            except mysql.connector.Error as e:
                messagebox.showerror("Error", f"Failed to save password: {str(e)}")

        ttk.Button(dialog, text="Save", command=save, style="success.TButton").pack(pady=20)

    def encrypt(self, text):
        # Simple XOR encryption (for demonstration - not for production use)
        if not self.encryption_key:
            return text
        key_bytes = self.encryption_key.encode()
        text_bytes = text.encode()
        encrypted = bytearray()
        for i in range(len(text_bytes)):
            encrypted.append(text_bytes[i] ^ key_bytes[i % len(key_bytes)])
        return base64.b64encode(encrypted).decode()

    def decrypt(self, encrypted_text):
        # Simple XOR decryption
        if not self.encryption_key:
            return encrypted_text
        try:
            encrypted_bytes = base64.b64decode(encrypted_text.encode())
            key_bytes = self.encryption_key.encode()
            decrypted = bytearray()
            for i in range(len(encrypted_bytes)):
                decrypted.append(encrypted_bytes[i] ^ key_bytes[i % len(key_bytes)])
            return decrypted.decode()
        except:
            messagebox.showerror("Error", "Decryption failed!")
            return None

    def edit_password(self):
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to edit.")
            return

        # Get password details
        item = self.password_tree.item(selection[0])
        service = item['values'][0]

        try:
            self.cursor.execute('SELECT * FROM passwords WHERE service = %s', (service,))
            password_data = self.cursor.fetchone()
            if not password_data:
                messagebox.showerror("Error", "Password not found!")
                return

            # Create edit dialog
            dialog = ttk.Toplevel(self.root)
            dialog.title("Edit Password")
            dialog.geometry("400x300")

            # Form fields
            ttk.Label(dialog, text="Service:", font=("Helvetica", 12)).pack(pady=5)
            service_entry = ttk.Entry(dialog, font=("Helvetica", 12))
            service_entry.insert(0, password_data[1])
            service_entry.pack(pady=5)

            ttk.Label(dialog, text="Username:", font=("Helvetica", 12)).pack(pady=5)
            username_entry = ttk.Entry(dialog, font=("Helvetica", 12))
            username_entry.insert(0, password_data[2])
            username_entry.pack(pady=5)

            ttk.Label(dialog, text="Password:", font=("Helvetica", 12)).pack(pady=5)
            password_entry = ttk.Entry(dialog, show="●", font=("Helvetica", 12))
            password_entry.insert(0, self.decrypt(password_data[3]))
            password_entry.pack(pady=5)

            ttk.Label(dialog, text="Category:", font=("Helvetica", 12)).pack(pady=5)
            category_var = tk.StringVar(value=password_data[4] or "Personal")
            category_combo = ttk.Combobox(dialog, textvariable=category_var,
                                          values=["Personal", "Work", "Finance", "Social"], font=("Helvetica", 12))
            category_combo.pack(pady=5)

            def save_changes():
                new_service = service_entry.get()
                new_username = username_entry.get()
                new_password = password_entry.get()
                new_category = category_var.get()

                if not all([new_service, new_username, new_password]):
                    messagebox.showerror("Error", "All fields are required!")
                    return

                try:
                    now = datetime.now().isoformat()
                    self.cursor.execute('''
                    UPDATE passwords 
                    SET service = %s, username = %s, encrypted_password = %s, 
                        category = %s, last_modified = %s
                    WHERE service = %s
                    ''', (new_service, new_username, self.encrypt(new_password),
                          new_category, now, service))

                    self.conn.commit()
                    self.update_password_list()
                    dialog.destroy()
                    messagebox.showinfo("Success", "Password updated successfully!")

                except mysql.connector.Error as e:
                    messagebox.showerror("Error", f"Failed to update password: {str(e)}")

            ttk.Button(dialog, text="Save Changes", command=save_changes, style="success.TButton").pack(pady=20)

        except mysql.connector.Error as e:
            messagebox.showerror("Error", f"Failed to retrieve password: {str(e)}")

    def delete_password(self):
        selection = self.password_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a password to delete.")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this password?"):
            item = self.password_tree.item(selection[0])
            service = item['values'][0]

            try:
                self.cursor.execute('DELETE FROM passwords WHERE service = %s', (service,))
                self.conn.commit()
                self.update_password_list()
                messagebox.showinfo("Success", "Password deleted successfully!")
            except mysql.connector.Error as e:
                messagebox.showerror("Error", f"Failed to delete password: {str(e)}")

    def update_password_list(self):
        self.search_passwords()

    def add_note(self):
        dialog = ttk.Toplevel(self.root)
        dialog.title("Add Secure Note")
        dialog.geometry("500x400")

        ttk.Label(dialog, text="Title:", font=("Helvetica", 12)).pack(pady=5)
        title_entry = ttk.Entry(dialog, width=50, font=("Helvetica", 12))
        title_entry.pack(pady=5)

        ttk.Label(dialog, text="Content:", font=("Helvetica", 12)).pack(pady=5)
        content_text = tk.Text(dialog, height=10, width=50, font=("Helvetica", 12))
        content_text.pack(pady=5)

        ttk.Label(dialog, text="Category:", font=("Helvetica", 12)).pack(pady=5)
        category_var = tk.StringVar(value="Personal")
        category_combo = ttk.Combobox(dialog, textvariable=category_var,
                                      values=["Personal", "Work", "Finance", "Social"], font=("Helvetica", 12))
        category_combo.pack(pady=5)

        def save_note():
            title = title_entry.get()
            category = category_var.get()
            content = content_text.get("1.0", tk.END.strip())

            if not all([title, content]):
                messagebox.showerror("Error", "Title and content are required!")
                return

            try:
                now = datetime.now().isoformat()
                self.cursor.execute('''
                INSERT INTO secure_notes (title, encrypted_content, category, created_date, last_modified)
                VALUES (%s, %s, %s, %s, %s)
                ''', (title, self.encrypt(content), category, now, now))

                self.conn.commit()
                self.update_notes_list()
                dialog.destroy()
                messagebox.showinfo("Success", "Note saved successfully!")

            except mysql.connector.Error as e:
                messagebox.showerror("Error", f"Failed to save note: {str(e)}")

        ttk.Button(dialog, text="Save Note", command=save_note, style="success.TButton").pack(pady=20)

    def edit_note(self):
        selection = self.notes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a note to edit.")
            return

        item = self.notes_tree.item(selection[0])
        title = item['values'][0]

        try:
            self.cursor.execute('SELECT * FROM secure_notes WHERE title = %s', (title,))
            note_data = self.cursor.fetchone()
            if not note_data:
                messagebox.showerror("Error", "Note not found!")
                return

            dialog = ttk.Toplevel(self.root)
            dialog.title("Edit Secure Note")
            dialog.geometry("500x400")

            ttk.Label(dialog, text="Title:", font=("Helvetica", 12)).pack(pady=5)
            title_entry = ttk.Entry(dialog, width=50, font=("Helvetica", 12))
            title_entry.insert(0, note_data[1])
            title_entry.pack(pady=5)

            ttk.Label(dialog, text="Category:", font=("Helvetica", 12)).pack(pady=5)
            category_var = tk.StringVar(value=note_data[3] or "Personal")
            category_combo = ttk.Combobox(dialog, textvariable=category_var,
                                          values=["Personal", "Work", "Finance", "Social"], font=("Helvetica", 12))
            category_combo.pack(pady=5)

            ttk.Label(dialog, text="Content:", font=("Helvetica", 12)).pack(pady=5)
            content_text = tk.Text(dialog, height=10, width=50, font=("Helvetica", 12))
            content_text.insert("1.0", self.decrypt(note_data[2]))
            content_text.pack(pady=5)

            def save_changes():
                new_title = title_entry.get()
                new_category = category_var.get()
                new_content = content_text.get("1.0", tk.END.strip())

                if not all([new_title, new_content]):
                    messagebox.showerror("Error", "Title and content are required!")
                    return

                try:
                    now = datetime.now().isoformat()
                    self.cursor.execute('''
                    UPDATE secure_notes 
                    SET title = %s, encrypted_content = %s, category = %s, last_modified = %s
                    WHERE title = %s
                    ''', (new_title, self.encrypt(new_content), new_category, now, title))

                    self.conn.commit()
                    self.update_notes_list()
                    dialog.destroy()
                    messagebox.showinfo("Success", "Note updated successfully!")

                except mysql.connector.Error as e:
                    messagebox.showerror("Error", f"Failed to update note: {str(e)}")

            ttk.Button(dialog, text="Save Changes", command=save_changes, style="success.TButton").pack(pady=20)

        except mysql.connector.Error as e:
            messagebox.showerror("Error", f"Failed to retrieve note: {str(e)}")

    def delete_note(self):
        selection = self.notes_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a note to delete.")
            return

        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this note?"):
            item = self.notes_tree.item(selection[0])
            title = item['values'][0]

            try:
                self.cursor.execute('DELETE FROM secure_notes WHERE title = %s', (title,))
                self.conn.commit()
                self.update_notes_list()
                messagebox.showinfo("Success", "Note deleted successfully!")
            except mysql.connector.Error as e:
                messagebox.showerror("Error", f"Failed to delete note: {str(e)}")

    def update_notes_list(self):
        for item in self.notes_tree.get_children():
            self.notes_tree.delete(item)

        try:
            self.cursor.execute('SELECT * FROM secure_notes ORDER BY title')
            notes = self.cursor.fetchall()

            for note in notes:
                self.notes_tree.insert('', 'end', values=(
                    note[1],  # title
                    note[3],  # category
                    note[5]  # last_modified
                ))
        except mysql.connector.Error as e:
            messagebox.showerror("Error", f"Failed to update notes list: {str(e)}")

    def backup_database(self):
        try:
            backup_path = filedialog.asksaveasfilename(
                defaultextension=".sql",
                filetypes=[("SQL File", "*.sql")],
                title="Save Database Backup"
            )
            if backup_path:
                os.system(f"mysqldump -u root -proot password_manager > {backup_path}")
                messagebox.showinfo("Success", f"Database backed up to {backup_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to backup database: {str(e)}")

    def restore_database(self):
        try:
            restore_path = filedialog.askopenfilename(
                filetypes=[("SQL File", "*.sql")],
                title="Select Database to Restore"
            )
            if restore_path:
                os.system(f"mysql -u root -proot password_manager < {restore_path}")
                messagebox.showinfo("Success", "Database restored successfully!")

                # Refresh the GUI to reflect the restored data
                self.update_password_list()
                self.update_notes_list()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to restore database: {str(e)}")

    def change_master_password(self):
        dialog = ttk.Toplevel(self.root)
        dialog.title("Change Master Password")
        dialog.geometry("400x200")

        ttk.Label(dialog, text="Current Password:", font=("Helvetica", 12)).pack(pady=5)
        current_pass = ttk.Entry(dialog, show="●", font=("Helvetica", 12))
        current_pass.pack(pady=5)

        ttk.Label(dialog, text="New Password:", font=("Helvetica", 12)).pack(pady=5)
        new_pass = ttk.Entry(dialog, show="●", font=("Helvetica", 12))
        new_pass.pack(pady=5)

        ttk.Label(dialog, text="Confirm New Password:", font=("Helvetica", 12)).pack(pady=5)
        confirm_pass = ttk.Entry(dialog, show="●", font=("Helvetica", 12))
        confirm_pass.pack(pady=5)

        def change_password():
            if not all([current_pass.get(), new_pass.get(), confirm_pass.get()]):
                messagebox.showerror("Error", "All fields are required!")
                return

            if new_pass.get() != confirm_pass.get():
                messagebox.showerror("Error", "New passwords do not match!")
                return

            if len(new_pass.get()) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters!")
                return

            current_hash = hashlib.sha256(current_pass.get().encode()).hexdigest()
            if current_hash != self.master_password_hash:
                messagebox.showerror("Error", "Current password is incorrect!")
                return

            self.master_password_hash = hashlib.sha256(new_pass.get().encode()).hexdigest()
            self.encryption_key = new_pass.get()

            # Generate new 2FA secret
            self.two_factor_secret = pyotp.random_base32()

            try:
                self.cursor.execute('''
                UPDATE users 
                SET master_password_hash = %s, two_factor_secret = %s 
                WHERE id = 1
                ''', (self.master_password_hash, self.two_factor_secret))
                self.conn.commit()
                dialog.destroy()
                messagebox.showinfo("Success", "Master password changed successfully!")
                self.show_2fa_setup()
            except mysql.connector.Error as e:
                messagebox.showerror("Error", f"Failed to update master password: {str(e)}")

        ttk.Button(dialog, text="Change Password", command=change_password, style="success.TButton").pack(pady=20)

    def run(self):
        self.root.mainloop()

    def search_passwords(self):
        search_term = self.search_var.get().lower()
        category = self.category_var.get()

        self.update_password_list(search_term, category)

    def update_password_list(self, search_term="", category="All"):
        # Clear existing items
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)

        try:
            query = "SELECT * FROM passwords"
            params = []

            if search_term or category != "All":
                query += " WHERE "
                conditions = []

                if search_term:
                    conditions.append("LOWER(service) LIKE %s OR LOWER(username) LIKE %s")
                    params.extend([f"%{search_term}%", f"%{search_term}%"])

                if category != "All":
                    conditions.append("category = %s")
                    params.append(category)

                query += " AND ".join(conditions)

            query += " ORDER BY service"
            self.cursor.execute(query, params)
            passwords = self.cursor.fetchall()

            for password in passwords:
                self.password_tree.insert('', 'end', values=(
                    password[1],  # service
                    password[2],  # username
                    password[4],  # category
                    password[8],  # last_modified
                    password[7]  # expiry_date
                ))
        except mysql.connector.Error as e:
            messagebox.showerror("Error", f"Failed to update password list: {str(e)}")

    def check_database_setup(self):
        try:
            self.cursor.execute("SELECT * FROM users WHERE id = 1")
            user_data = self.cursor.fetchone()
            if user_data:
                messagebox.showinfo("Database Check", f"User data found. 2FA Secret: {user_data[2][:5]}...")
            else:
                messagebox.showwarning("Database Check", "No user data found. Please set up a master password.")
        except mysql.connector.Error as e:
            messagebox.showerror("Database Error", f"Failed to check database: {str(e)}")


def main():
    app = AdvancedPasswordManager()
    app.run()


if __name__ == "__main__":
    main()

