import tkinter as tk
from tkinter import messagebox
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
import pyotp
import qrcode
from PIL import Image, ImageTk
import io

class TwoFactorAuth:
    def setup_2fa(self, parent, on_success=None):
        """Show 2FA setup page"""
        self.parent = parent
        self.on_success = on_success
        
        # Generate new secret key
        self.secret = pyotp.random_base32()
        
        # Instructions
        instructions = """
1. Install an authenticator app (like Google Authenticator)
2. Scan the QR code below or enter the secret key manually
3. Enter the 6-digit code shown in your authenticator app
        """
        ttk.Label(
            self.parent,
            text=instructions,
            font=('Helvetica', 12),
            justify='left'
        ).pack(pady=10)
        
        # Generate and display QR code
        totp = pyotp.TOTP(self.secret)
        uri = totp.provisioning_uri("Advanced Password Manager", issuer_name="Password Manager")
        
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        qr_image = qr.make_image(fill_color="black", back_color="white")
        
        # Convert PIL image to PhotoImage
        img_byte_arr = io.BytesIO()
        qr_image.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        qr_photo = ImageTk.PhotoImage(data=img_byte_arr)
        qr_label = ttk.Label(self.parent, image=qr_photo)
        qr_label.image = qr_photo  # Keep a reference!
        qr_label.pack(pady=10)
        
        # Display manual key
        ttk.Label(
            self.parent,
            text="Manual Key:",
            font=('Helvetica', 14, 'bold')
        ).pack(pady=(20, 5))

        manual_key_frame = ttk.Frame(self.parent)
        manual_key_frame.pack(pady=5)

        manual_key_label = ttk.Label(
            manual_key_frame,
            text=self.secret,
            font=('Courier', 16, 'bold')
        )
        manual_key_label.pack(side='left', padx=5)

        def copy_key():
            self.parent.clipboard_clear()
            self.parent.clipboard_append(self.secret)
            messagebox.showinfo("Success", "Manual key copied to clipboard!")

        ttk.Button(
            manual_key_frame,
            text="Copy",
            command=copy_key,
            style="info.TButton",
            width=10
        ).pack(side='left', padx=5)
        
        # Verification section
        ttk.Label(
            self.parent,
            text="Enter the 6-digit code from your authenticator app:",
            font=('Helvetica', 12)
        ).pack(pady=10)
        
        self.code_entry = ttk.Entry(self.parent, font=('Helvetica', 12), width=10, justify='center')
        self.code_entry.pack(pady=5)
        
        ttk.Button(
            self.parent,
            text="Verify",
            command=self.verify_setup_code,
            style="success.TButton",
            width=20
        ).pack(pady=20)

    def verify_setup_code(self):
        entered_code = self.code_entry.get().strip()
        totp = pyotp.TOTP(self.secret)
        if totp.verify(entered_code):
            if self.on_success:
                self.on_success(self.secret)
        else:
            messagebox.showerror("Error", "Invalid code. Please try again.")

    def verify_2fa(self, parent, secret, on_success=None):
        """Show 2FA verification page"""
        self.parent = parent
        self.secret = secret
        self.on_success = on_success
        
        ttk.Label(
            self.parent,
            text="Enter the 6-digit code from your authenticator app:",
            font=('Helvetica', 12)
        ).pack(pady=10)
        
        self.code_entry = ttk.Entry(self.parent, font=('Helvetica', 12), width=10, justify='center')
        self.code_entry.pack(pady=10)
        
        ttk.Button(
            self.parent,
            text="Verify",
            command=self.verify_login_code,
            style="success.TButton",
            width=20
        ).pack(pady=20)

    def verify_login_code(self):
        entered_code = self.code_entry.get().strip()
        totp = pyotp.TOTP(self.secret)
        if totp.verify(entered_code):
            if self.on_success:
                self.on_success()
        else:
            messagebox.showerror("Error", "Invalid code. Please try again.")
