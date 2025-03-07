  ![Pika Vault Logo](/assets/git-1.png)
## Pika Vault ⚡

_A Pikachu-powered password manager with a zap of security!_

Pika Vault is a sleek, modern password manager built with Python, featuring master password protection, TOTP-based 2FA, and encrypted storage. With a customtkinter GUI and a dash of Pokémon flair, it’s your electrifying solution to keeping credentials safe!
## Features ✨

- **Master Password**: Secure your vault with a strong key.
- **2FA with TOTP**: Generate QR codes for extra Pikachu-level protection.
- **Password Generator**: Zap out strong, random passwords.
- **Encryption**: Powered by Fernet (symmetric encryption) and PBKDF2.
- **SQLite Storage**: Keeps your secrets in a local, secure database.
- **Cool UI**: Dark mode with a Pikachu-inspired background (optional).

## Getting Started ⚡
### Prerequisites

You’ll need these to unleash Pika Vault:

    Python 3.8+
    pip (Python package manager)

### Installation
#### Clone the Repo

    git clone https://github.com/husnain002/pika-vault.git
    cd pika-vault

#### Install Dependencies
Zap in the required packages:


    pip install customtkinter pillow pyotp qrcode cryptography argon2-cffi
#### Add Background Image
Download pika-back2.jpg (a Pikachu-themed image) and place it in the project folder. If missing, Pika Vault defaults to a sleek dark background.

### Running the Code
#### Launch the Vault

    python pika_passwordmanager.py
#### First Time?
     -  Set up your master password (min 12 characters).
     -  Generate a 2FA QR code and scan it with an authenticator app (e.g., Google Authenticator).
     -  Create your vault and start storing credentials!
#### Log In
    - Use your master password and TOTP code to unlock the vault. Pika’s watching—don’t mess up too many times, or you’ll get a 30-second timeout!

## Usage ⚡

    Add Credentials: Enter a website, username, and password (or generate one).
    View Vault: Toggle visibility with "Hide/Show Pika Vault".
    Delete: Zap away unwanted entries with the trash button.
    Lock It: Hit "Lock" to secure your vault anytime.

### Main Screen
![image](https://github.com/user-attachments/assets/eb5db3e6-b43b-483b-9223-74dfabd323c6)

### Enter Password and Generate 2FA
![image](https://github.com/user-attachments/assets/65274d8a-c7e9-4123-bab2-b13990a8f341)

### Login into the Vault using the master password and the OTP from Google Authenticator
![image](https://github.com/user-attachments/assets/200cfc1a-09fa-4dc9-882b-a115470f03d6)

### Main Dashboard 
![image](https://github.com/user-attachments/assets/463cbcb2-490c-4546-a673-766cbbfd660e)

### Pika Vault
![image](https://github.com/user-attachments/assets/9ad9e912-b9b8-4b4f-8ff3-afbadaf321d2)



## Security Notes 🔒

    Passwords are hashed with Argon2 and encrypted with Fernet.
    The database (pika_vault.db) is locked down with 0600 permissions (Unix-like systems).
    Failed login attempts trigger a lockout—Pika doesn’t mess around!



## Contributing

Got a thunderbolt of an idea? Fork this repo, make your changes, and send a pull request. Let’s make Pika Vault shockingly awesome together!

## License

This project is licensed under the MIT License—feel free to zap it into your own projects!

_**Pika Pika! Ready to secure your digital world with the power of Pikachu? Clone, run, and enjoy! ⚡**_
