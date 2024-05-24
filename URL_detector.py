import re
import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import messagebox

# URL Analysis Function
def is_suspicious_url(url):
    ip_pattern = re.compile(r"http[s]?://(\d{1,3}\.){3}\d{1,3}")
    if ip_pattern.search(url):
        return True

    if len(url) > 75:
        return True

    suspicious_keywords = ['login', 'verify', 'bank', 'update', 'secure']
    if any(keyword in url.lower() for keyword in suspicious_keywords):
        return True

    return False

# Email Analysis Function
def is_suspicious_email(content):
    phishing_keywords = ['password', 'login', 'verify', 'update', 'account', 'urgent']
    if any(keyword in content.lower() for keyword in phishing_keywords):
        return True

    url_pattern = re.compile(r'http[s]?://[^\s]+')
    urls = url_pattern.findall(content)
    for url in urls:
        if is_suspicious_url(url):
            return True

    return False

# Functions for GUI buttons
def check_url():
    url = url_entry.get()
    if is_suspicious_url(url):
        messagebox.showwarning("Phishing Alert", "The URL looks suspicious!")
    else:
        messagebox.showinfo("Safe", "The URL seems safe.")

def check_email():
    content = email_text.get("1.0", tk.END)
    if is_suspicious_email(content):
        messagebox.showwarning("Phishing Alert", "The email content looks suspicious!")
    else:
        messagebox.showinfo("Safe", "The email content seems safe.")

# Creating the main GUI window
root = tk.Tk()
root.title("Phishing Detector")

# URL Checker UI
tk.Label(root, text="Enter URL:").pack()
url_entry = tk.Entry(root, width=50)
url_entry.pack()
tk.Button(root, text="Check URL", command=check_url).pack()

# Email Checker UI
tk.Label(root, text="Enter Email Content:").pack()
email_text = tk.Text(root, height=10, width=50)
email_text.pack()
tk.Button(root, text="Check Email", command=check_email).pack()

# Run the application
root.mainloop()
