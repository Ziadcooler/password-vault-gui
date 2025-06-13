import tkinter as tk
import base64
import hashlib
import os 
from cryptography.fernet import Fernet
import json
import time

MASTER_FILE = "master.hash"
VAULT_FILE = "vault.dat"

showPass = False 

window = tk.Tk()
window.title("Password Vault")
window.geometry("500x400")

pw = ""

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def showPassword():
    global showPass
    showPass = not showPass
    if showPass:
        entry.config(show="")
        button2.config(text="Hide Password")
    else:
        entry.config(show="*")
        button2.config(text="Show Password")


def setMasterPass():
    global button2
    if not os.path.exists(MASTER_FILE):
        entry.config(state="normal")
        label.config(text="Set a new master password.")
        button.config(text="Submit", command = confirmMasterPass)
        button2 = tk.Button(text="Hide Password", command = showPassword)
        button2.pack()

def confirmMasterPass():
    global pw1
    pw1 = entry.get()
    entry.delete(0, tk.END)
    label.config(text="Confirm password.")
    button.config(text="Confirm", command = finishMasterPass)

def finishMasterPass():
    global button2
    pw2 = entry.get()
    if pw1 != pw2:
        label.config(text="Passwords do not match. Reset the process.")
        entry.delete(0, tk.END)
        entry.config(state="disabled")
        button.config(text="Reset", command = setMasterPass)
        button2.destroy()
        return 
    with open(MASTER_FILE, "w") as f:
        f.write(hash_password(pw1))
    label.config(text="Master password set!")
    entry.delete(0, tk.END)
    entry.config(state="disabled")
    button.config(text="Login", command = login)
    button2.destroy()

def login():
    global button2
    label.config(text="Enter your master password.")
    entry.config(state="normal")
    button.config(text="Submit", command = checkLogin)
    button2 = tk.Button(text="Hide Password", command = showPassword)
    button2.pack()

def checkLogin():
    global pw, key, fernet, salt, entries, button2
    pw = entry.get()
    entry.delete(0, tk.END)
    with open(MASTER_FILE, "r") as f:
        saved = f.read()
    if hash_password(pw) == saved:
        salt = b'static_salt_123456'
        key = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 100000)
        key = base64.urlsafe_b64encode(key)
        fernet = Fernet(key)
        entries = load_entries(fernet)  # Only load if password is correct

        label.config(text="Access Granted.")
        entry.config(state="disabled")
        button2.destroy()
        button.config(text="Continue", command=vault)
    else:
        label.config(text="Access Denied.")
        button.config(text="Try Again", command=login)


def vault():
    global button, button2, button3
    label.config(text="The Vault")
    
    button.config(text="New Entry", command = newEntry_site)
    
    button2 = tk.Button(text="See Saved Entries", command = checkSavedEntries)
    button2.pack()

    button3 = tk.Button(text="Exit", command = quit)
    button3.pack()

def save_entries(entries, fernet):
    global encrypted
    data = json.dumps(entries).encode()
    encrypted = fernet.encrypt(data)
    with open(VAULT_FILE, "wb") as f:
        f.write(encrypted)

def load_entries(fernet):
    global encrypted, button, button2, button3
    if not os.path.exists(VAULT_FILE):
        return []
    with open(VAULT_FILE, "rb") as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted).decode()
        return json.loads(decrypted)
    except:
        label.config(text="Failed to access vault.")
        button.config(text="Quit", command = quit)
        if 'button2' in globals():
            button2.destroy()
        if 'button3' in globals():
            button3.destroy()

        return []

def checkSavedEntries():
    button2.destroy()
    text = ""
    for entry in entries:
        text += f"\n{entry['site']}: {entry['username']} / {entry['password']}"
    label.config(text=text)


def newEntry_site():
    global button2
    label.config(text="Type in the site!")
    entry.config(state="normal")
    button.config(text="Submit", command = newEntry_username)
    button2.config(text = "Show", command = showPassword)

def newEntry_username():
    global site
    site = entry.get()
    entry.delete(0, tk.END)
    label.config(text= "Type in the username!")
    button.config(text="Submit", command = newEntry_password)

def newEntry_password():
    global username
    username = entry.get()
    entry.delete(0, tk.END)
    label.config(text= "Type in the password!")
    button.config(text="Submit", command = newEntry_save)

def newEntry_save():
    global username, password, site
    password = entry.get()
    entry.delete(0, tk.END)
    label.config(text = "Entry Saved!")
    button.config(text="Back to Vault", command = vault)
    entries.append({
        "site": site,
        "username": username,
        "password": password
    })
    save_entries(entries, fernet)


label = tk.Label(text = "Welcome to the password vault!")
label.pack()

entry = tk.Entry(state="disabled")
entry.pack()

button = tk.Button(text="Start", command = setMasterPass if not os.path.exists(MASTER_FILE) else login)
button.pack()

window.mainloop()