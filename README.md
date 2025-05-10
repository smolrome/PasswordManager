# 🔐 Secure Password Manager

A secure, encrypted password manager with a user-friendly GUI built with Python and Tkinter. 
Stores passwords in an encrypted SQLite database and includes features like password generation, emergency access, and activity logging.

---

## 🚀 Key Features

- 🔒 Master password protection with strong encryption (PBKDF2 + Fernet)
- 🛡️ Auto-locking after inactivity period (configurable)
- 📋 Password storage with service, username, URL, and notes
- 🔑 Secure password generator with customizable complexity
- 🚨 Emergency access system with trusted contacts
- 📊 Activity logging for security auditing
- 📤📥 Import/export functionality
- 🎨 Clean, modern dark theme UI

---

## 📦 Requirements

Make sure you have **Python 3.7+** installed and the following packages:

```bash
pip install tkinter pyperclip cryptography pillow
```

Or simply use:

```bash
pip install -r requirements.txt
```

---

## 🛠️ Installation

1. **Clone the repository**  
   ```bash
   git clone https://github.com/yourusername/password-manager.git
   cd password-manager
   ```

2. **Install dependencies**  
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**  
   ```bash
   python passManager.py
   ```

---

## 📐 File Structure

```
PasswordManager/
├── passManager.py          # Main application file
├── requirements.txt        # Python dependencies
└── README.md               # Project documentation
```

---

## 💡 Usage

### 🔐 Setting the Master Password
- On the first run, you’ll be prompted to **set a master password**.
- This password will be used to **encrypt** and **decrypt** all stored credentials.

### 📂 Adding and Managing Passwords
- **Add Password:** Store new credentials securely  
- **View Passwords:** View or copy saved passwords  
- **Edit or Delete:** Update or remove entries  

### 🔄 Password Generator
- Generate strong, random passwords with custom length and character options.

### 🔓 Emergency Access
- Grant emergency contacts access to your data after a configurable waiting period.

### 🔐 Security Features
- **Auto-Lock:** Automatically locks the app after a period of inactivity  
- **Activity Logs:** Tracks all security-related events  

---

## 🖼️ Screenshots

*(Consider adding actual screenshots of your application in action here)*

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the repository**  
2. **Create your feature branch** (`git checkout -b feature/amazing-feature`)  
3. **Commit your changes** (`git commit -m 'Add some amazing feature'`)  
4. **Push to the branch** (`git push origin feature/amazing-feature`)  
5. **Open a Pull Request**  

---

## 📜 License

This project is open for learning and collaboration under the [MIT License](./LICENSE).  
© 2025 [smolrome](https://github.com/smolrome)

---

## 📬 Contact

Connect with me:

- GitHub: [@smolrome](https://github.com/smolrome)  
- Email: jeromepedrosa3@gmail.com  
