import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox
import sqlite3
import secrets
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from argon2 import PasswordHasher
import pyotp
import qrcode
from PIL import Image
import io
import string

ph = PasswordHasher()

def init_db():
    conn = sqlite3.connect('pika_vault.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS passwords
                 (id INTEGER PRIMARY KEY, website TEXT, username TEXT, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS master
                 (id INTEGER PRIMARY KEY, hash TEXT, salt BLOB, totp_secret TEXT)''')
    conn.commit()
    conn.close()
    try:
        os.chmod('pika_vault.db', 0o600)
    except OSError:
        pass 

def generate_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return Fernet(key)

def encrypt_password(fernet, password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(fernet, encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

class PikaVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Pika Vault")
        self.geometry("600x600")
        self.resizable(False, False)
        
        ctk.set_appearance_mode("dark")
        
        try:
            bg_image = Image.open("pika-back2.jpg")  
            bg_image = bg_image.resize((600, 600), Image.Resampling.LANCZOS)
            self.bg_image = ctk.CTkImage(bg_image, size=(600, 600)) 
            self.bg_label = ctk.CTkLabel(self, image=self.bg_image, text="")
            self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        except FileNotFoundError:
            print("Background image 'pika-back1.jpg' not found. Using default background.")
            self.configure(fg_color="#1a1a1a")  
        
        self.master_password = None
        self.fernet = None
        self.totp_secret = None
        self.logged_in = False
        self.passwords_visible = True
        self.failed_attempts = 0
        self.lockout_active = False
        
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        conn = sqlite3.connect('pika_vault.db')
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM master")
        count = c.fetchone()[0]
        conn.close()
        
        if count == 0:
            self.show_setup_screen()
        else:
            self.show_login_screen()

    def show_setup_screen(self):
        self.clear_window()
        
        frame = ctk.CTkFrame(self, corner_radius=15, width=400, height=450, fg_color="#2b2b2b", border_color="#FFFF00", border_width=2)
        frame.pack(pady=30, padx=10, expand=True)
        
        ctk.CTkLabel(frame, text="Setup Your Pika Vault ⚡", font=("Pokemon Solid", 20, "bold"), text_color="#FFFF00").pack(pady=20)
        
        self.setup_pass_entry = ctk.CTkEntry(frame, placeholder_text="Pika Password", show="*", width=200, border_color="#FFFF00", fg_color="#1a1a1a", text_color="#FFFF00")
        self.setup_pass_entry.pack(pady=10)
        
        self.confirm_pass_entry = ctk.CTkEntry(frame, placeholder_text="Confirm Pika Password", show="*", width=200, border_color="#FFFF00", fg_color="#1a1a1a", text_color="#FFFF00")
        self.confirm_pass_entry.pack(pady=10)
        
        ctk.CTkButton(frame, text="Generate Pika 2FA", command=self.generate_totp, corner_radius=10, width=150, fg_color="#FFFF00", text_color="#000000", font=("Pokemon Solid", 12)).pack(pady=10)
        self.qr_label = ctk.CTkLabel(frame, text="")
        self.qr_label.pack(pady=10)
        
        ctk.CTkButton(frame, text="Create Pika Vault", command=self.setup_master, corner_radius=10, width=150, fg_color="#FFFF00", text_color="#000000", font=("Pokemon Solid", 12)).pack(pady=20)

    def generate_totp(self):
        self.totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(self.totp_secret)
        uri = totp.provisioning_uri("PikaVault", issuer_name="Pika")
        
        qr = qrcode.QRCode(box_size=5)
        qr.add_data(uri)
        qr.make()
        img = qr.make_image(fill_color="#FFFF00", back_color="#2b2b2b")
        img_byte_arr = io.BytesIO()
        img.save(img_byte_arr, format='PNG')
        img_byte_arr = img_byte_arr.getvalue()
        
        photo = ctk.CTkImage(Image.open(io.BytesIO(img_byte_arr)), size=(150, 150))  
        self.qr_label.configure(image=photo)

    def show_login_screen(self):
        self.clear_window()
        
        self.login_frame = ctk.CTkFrame(self, corner_radius=15, width=350, height=300, 
                                    fg_color="#3a3a3a", border_color="#FFFF00", border_width=2)
        self.login_frame.pack(pady=80, padx=80, expand=True)
        
        ctk.CTkLabel(self.login_frame, text="Welcome to Pika Vault ⚡", font=("Pokemon Solid", 20, "bold"), 
                    text_color="#FFFF00").pack(pady=20)
        
        self.login_pass_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Pika Password", show="*", 
                                            width=200, border_color="#FFFF00", fg_color="#1a1a1a", text_color="#FFFF00")
        self.login_pass_entry.pack(pady=10)
        
        self.totp_entry = ctk.CTkEntry(self.login_frame, placeholder_text="Pika 2FA Code", width=200, 
                                    border_color="#FFFF00", fg_color="#1a1a1a", text_color="#FFFF00")
        self.totp_entry.pack(pady=10)
        
        self.unlock_button = ctk.CTkButton(self.login_frame, text="Unlock Pika Vault", command=self.verify_login, 
                                        corner_radius=10, width=150, height=40, fg_color="#FFFF00", 
                                        text_color="#000000", font=("Pokemon Solid", 14))
        self.unlock_button.pack(pady=20)

    def show_dashboard(self):
        self.clear_window()
        
        self.main_frame = ctk.CTkFrame(self, corner_radius=10, fg_color="#2b2b2b", border_color="#FFFF00", border_width=2)
        self.main_frame.pack(pady=10, padx=10, fill="both", expand=True)
        
        header_frame = ctk.CTkFrame(self.main_frame, corner_radius=0, fg_color="#1a1a1a")
        header_frame.pack(fill="x", pady=(0, 10))
        
        ctk.CTkLabel(header_frame, text="Pika Vault ⚡", font=("Pokemon Solid", 16, "bold"), text_color="#FFFF00").pack(side="left", padx=10)
        ctk.CTkButton(header_frame, text="ℹ About", command=self.show_about, width=60,
                     fg_color="#FFFF00", text_color="#000000", font=("Pokemon Solid", 12)).pack(side="right", padx=5)
        ctk.CTkButton(header_frame, text="🔒 Lock", command=self.lock_app, width=60, 
                     fg_color="#FF5555", hover_color="#FF7777", font=("Pokemon Solid", 12)).pack(side="right", padx=10)
        
        add_frame = ctk.CTkFrame(self.main_frame, corner_radius=5, fg_color="#3a3a3a")
        add_frame.pack(fill="x", pady=5, padx=5)
        
        self.website_entry = ctk.CTkEntry(add_frame, placeholder_text="Website", width=180, border_color="#FFFF00", fg_color="#1a1a1a", text_color="#FFFF00")
        self.website_entry.pack(side="left", padx=5, pady=5)
        
        self.username_entry = ctk.CTkEntry(add_frame, placeholder_text="Username", width=180, border_color="#FFFF00", fg_color="#1a1a1a", text_color="#FFFF00")
        self.username_entry.pack(side="left", padx=5, pady=5)
        
        self.password_entry = ctk.CTkEntry(add_frame, placeholder_text="Password", width=180, border_color="#FFFF00", fg_color="#1a1a1a", text_color="#FFFF00")
        self.password_entry.pack(side="left", padx=5, pady=5)
        
        buttons_frame = ctk.CTkFrame(self.main_frame, corner_radius=5, fg_color="#3a3a3a")
        buttons_frame.pack(fill="x", pady=5, padx=5)
        
        ctk.CTkButton(buttons_frame, text="Generate Pika Pass", command=self.generate_password, width=100,
                     corner_radius=5, fg_color="#FFFF00", text_color="#000000", font=("Pokemon Solid", 12)).pack(side="left", padx=5)
        ctk.CTkButton(buttons_frame, text="Save to Vault", command=self.save_password, width=100,
                     corner_radius=5, fg_color="#FFFF00", text_color="#000000", font=("Pokemon Solid", 12)).pack(side="left", padx=5)
        
        self.credentials_frame = ctk.CTkFrame(self.main_frame, fg_color="#2b2b2b")
        self.credentials_frame.pack(fill="both", expand=True, pady=5, padx=5)
        
        self.toggle_button = ctk.CTkButton(self.credentials_frame, text="Hide Pika Vault", 
                                         command=self.toggle_credentials, width=100,
                                         corner_radius=5, fg_color="#FFFF00", text_color="#000000", font=("Pokemon Solid", 12))
        self.toggle_button.pack(pady=5)
        
        self.headers_frame = ctk.CTkFrame(self.credentials_frame, fg_color="#3a3a3a")
        self.headers_frame.pack(fill="x")
        
        ctk.CTkLabel(self.headers_frame, text="Website", width=130, font=("Pokemon Solid", 12, "bold"), text_color="#FFFF00").pack(side="left", padx=2)
        ctk.CTkLabel(self.headers_frame, text="Username", width=130, font=("Pokemon Solid", 12, "bold"), text_color="#FFFF00").pack(side="left", padx=2)
        ctk.CTkLabel(self.headers_frame, text="Password", width=130, font=("Pokemon Solid", 12, "bold"), text_color="#FFFF00").pack(side="left", padx=2)
        ctk.CTkLabel(self.headers_frame, text="Action", width=100, font=("Pokemon Solid", 12, "bold"), text_color="#FFFF00").pack(side="left", padx=2)
        
        self.scroll_frame = ctk.CTkScrollableFrame(self.credentials_frame, height=300, fg_color="#2b2b2b")
        self.scroll_frame.pack(fill="both", expand=True, pady=5)
        
        self.refresh_credentials()

    def show_about(self):
        messagebox.showinfo("About Pika Vault", 
                          "Pika Vault Password Manager\n"
                          "Created by Husnain Shahid\n"
                          "Date: March 05, 2025\n"
                          "Website: https://husnainshahid.me/\n"
                          "Github: https://github.com/husnain002\n"
                          "A secure place for your Pika passwords!")

    def refresh_credentials(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()
            
        conn = sqlite3.connect('pika_vault.db')
        c = conn.cursor()
        c.execute("SELECT id, website, username, password FROM passwords")
        passwords = c.fetchall()
        conn.close()
        
        if not passwords:
            ctk.CTkLabel(self.scroll_frame, text="No Pika credentials yet!", font=("Pokemon Solid", 12), text_color="#FFFF00").pack(pady=20)
        else:
            self.password_labels = []
            for id_, website, username, encrypted_pass in passwords:
                password = decrypt_password(self.fernet, encrypted_pass)
                
                row_frame = ctk.CTkFrame(self.scroll_frame, fg_color="#2b2b2b")
                row_frame.pack(fill="x", pady=2)
                
                ctk.CTkLabel(row_frame, text=website[:20], width=130, font=("Pokemon Solid", 11), text_color="#FFFF00").pack(side="left", padx=2)
                ctk.CTkLabel(row_frame, text=username[:20], width=130, font=("Pokemon Solid", 11), text_color="#FFFF00").pack(side="left", padx=2)
                
                pass_label = ctk.CTkLabel(row_frame, text="••••••••", width=100, font=("Pokemon Solid", 11), text_color="#FFFF00")
                pass_label.pack(side="left", padx=2)
                self.password_labels.append((pass_label, password))
                
                show_btn = ctk.CTkButton(row_frame, text="👁", width=30, 
                                       command=lambda p=password, l=pass_label: self.toggle_password(p, l),
                                       corner_radius=5, fg_color="#FFFF00", text_color="#000000", font=("Pokemon Solid", 12))
                show_btn.pack(side="left", padx=2)
                
                delete_btn = ctk.CTkButton(row_frame, text="🗑", width=30, 
                                         command=lambda i=id_: self.delete_credential(i),
                                         fg_color="#FF5555", hover_color="#FF7777", font=("Pokemon Solid", 12))
                delete_btn.pack(side="left", padx=2)
                
        if not self.passwords_visible:
            self.hide_credentials()

    def toggle_password(self, password, label):
        if label.cget("text") == "••••••••":
            label.configure(text=password[:20])
        else:
            label.configure(text="••••••••")

    def toggle_credentials(self):
        if self.passwords_visible:
            self.hide_credentials()
            self.toggle_button.configure(text="Show Pika Vault")
            self.passwords_visible = False
        else:
            self.show_credentials()
            self.toggle_button.configure(text="Hide Pika Vault")
            self.passwords_visible = True

    def hide_credentials(self):
        self.headers_frame.pack_forget()
        self.scroll_frame.pack_forget()

    def show_credentials(self):
        self.headers_frame.pack(fill="x")
        self.scroll_frame.pack(fill="both", expand=True, pady=5)

    def delete_credential(self, credential_id):
        if messagebox.askyesno("Confirm Delete", "Pika wants to know: Delete this credential?"):
            conn = sqlite3.connect('pika_vault.db')
            c = conn.cursor()
            c.execute("DELETE FROM passwords WHERE id = ?", (credential_id,))
            conn.commit()
            conn.close()
            self.refresh_credentials()
            messagebox.showinfo("Success", "Pika says: Credential zapped!")

    def generate_password(self):
        alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
        password = ''.join(secrets.choice(alphabet) for _ in range(16))
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)

    def save_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not all([website, username, password]):
            messagebox.showerror("Error", "Pika needs all fields filled!")
            return
            
        encrypted_pass = encrypt_password(self.fernet, password)
        
        conn = sqlite3.connect('pika_vault.db')
        c = conn.cursor()
        c.execute("INSERT INTO passwords (website, username, password) VALUES (?, ?, ?)",
                 (website, username, encrypted_pass))
        conn.commit()
        conn.close()
        
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.refresh_credentials()
        messagebox.showinfo("Success", "Pika saved your credential!")

    def lock_app(self):
        self.logged_in = False
        self.master_password = None
        self.fernet = None
        self.totp_secret = None
        self.show_login_screen()

    def clear_window(self):
        for widget in self.winfo_children():
            if widget != self.bg_label: 
                widget.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Pika asks: Lock and quit?"):
            self.lock_app()
            self.destroy()

    def setup_master(self):
        password = self.setup_pass_entry.get()
        confirm = self.confirm_pass_entry.get()
        
        if password != confirm:
            messagebox.showerror("Error", "Pika says: Passwords don’t match!")
            return
        if not self.totp_secret:
            messagebox.showerror("Error", "Pika needs 2FA generated first!")
            return
        if len(password) < 12:
            messagebox.showerror("Error", "Pika demands at least 12 characters!")
            return
            
        salt = os.urandom(16)
        hash_pass = ph.hash(password)
        
        temp_fernet = generate_key(password, salt)
        encrypted_totp_secret = encrypt_password(temp_fernet, self.totp_secret)
        
        conn = sqlite3.connect('pika_vault.db')
        c = conn.cursor()
        c.execute("INSERT INTO master (hash, salt, totp_secret) VALUES (?, ?, ?)",
                 (hash_pass, salt, encrypted_totp_secret))
        conn.commit()
        conn.close()
        
        self.setup_pass_entry.delete(0, tk.END)
        self.confirm_pass_entry.delete(0, tk.END)
        self.totp_secret = None
        self.qr_label.configure(image=None)
        self.show_login_screen()

    def verify_login(self):
        if self.lockout_active:
            return  
        
        password = self.login_pass_entry.get()
        totp_code = self.totp_entry.get()
        
        conn = sqlite3.connect('pika_vault.db')
        c = conn.cursor()
        c.execute("SELECT hash, salt, totp_secret FROM master LIMIT 1")
        result = c.fetchone()
        conn.close()
        
        if not result:
            messagebox.showerror("Error", "Pika says: No vault set yet!")
            return
            
        stored_hash, salt, encrypted_totp_secret = result
        temp_fernet = generate_key(password, salt)
        
        try:
            if ph.verify(stored_hash, password):
                self.totp_secret = decrypt_password(temp_fernet, encrypted_totp_secret)
                totp = pyotp.TOTP(self.totp_secret)
                if totp.verify(totp_code):
                    self.master_password = password
                    self.fernet = temp_fernet
                    self.logged_in = True
                    self.failed_attempts = 0
                    self.show_dashboard()
                else:
                    raise ValueError("Invalid TOTP")
            else:
                raise ValueError("Invalid password")
        except Exception:
            self.failed_attempts += 1
            messagebox.showerror("Error", "Pika zapped: Invalid credentials!")
            
            self.lockout_active = True
            self.unlock_button.configure(state="disabled")
            self.after(2000, self._reset_lockout)  
            
            if self.failed_attempts >= 5:
                messagebox.showerror("Locked", "Pika’s mad: Wait 30 seconds!")
                self.after(30000, self._reset_lockout_after_long_delay)  

    def _reset_lockout(self):
        self.lockout_active = False
        self.unlock_button.configure(state="normal")

    def _reset_lockout_after_long_delay(self):
        self.failed_attempts = 0
        self.lockout_active = False
        self.unlock_button.configure(state="normal")

if __name__ == "__main__":
    init_db()
    app = PikaVaultApp()
    app.mainloop()