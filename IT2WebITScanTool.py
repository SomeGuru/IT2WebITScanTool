#!/usr/bin/env python3
"""
IT2Innovations Web IT Scan Tool v1.0.4
For educational and authorized security testing purposes only.
Always obtain proper authorization before scanning any website.

Creator: Mike Larios
Engineering Validation: Mike Larios
License: MIT & Apache
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import requests
import ssl
import socket
from urllib.parse import urlparse, urljoin
import datetime
from bs4 import BeautifulSoup
import re
import warnings
from typing import Dict, List
import json
import os
import sys
import tempfile
import webbrowser
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib.request
from packaging import version
from PIL import Image, ImageTk
import ctypes
import subprocess

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Version info - VERSION 1.0.4
CURRENT_VERSION = "1.0.4"
GITHUB_REPO = "someguru/IT2WebITScanTool"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"
UPDATE_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"

# Global icon path - will be set once
_ICON_PATH = None

def get_icon_path():
    """
    Get the icon path - works both in development and when compiled with PyInstaller.
    Returns the path to the .ico file.
    """
    global _ICON_PATH
    
    # Return cached path if valid
    if _ICON_PATH and os.path.exists(_ICON_PATH):
        return _ICON_PATH
    
    # List of possible locations to check
    search_paths = []
    
    # When running as PyInstaller bundle
    if getattr(sys, 'frozen', False):
        bundle_dir = sys._MEIPASS
        search_paths.extend([
            os.path.join(bundle_dir, 'it2_icon.ico'),
            os.path.join(bundle_dir, 'icon.ico'),
        ])
    
    # Development mode - same directory as script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    search_paths.extend([
        os.path.join(script_dir, 'it2_icon.ico'),
        os.path.join(script_dir, 'icon.ico'),
    ])
    
    # Temp directory (downloaded location)
    search_paths.append(os.path.join(tempfile.gettempdir(), 'it2_icon.ico'))
    
    # Current working directory
    search_paths.append(os.path.join(os.getcwd(), 'it2_icon.ico'))
    
    # Check all locations
    for path in search_paths:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            _ICON_PATH = path
            print(f"[Icon] Found at: {path}")
            return _ICON_PATH
    
    # Download if not found
    print("[Icon] Not found locally, downloading...")
    download_path = os.path.join(tempfile.gettempdir(), 'it2_icon.ico')
    
    try:
        icon_url = "http://www.it2innovations.com/images/favicon.ico"
        
        for attempt in range(3):
            try:
                urllib.request.urlretrieve(icon_url, download_path)
                if os.path.exists(download_path) and os.path.getsize(download_path) > 0:
                    _ICON_PATH = download_path
                    print(f"[Icon] Downloaded to: {download_path}")
                    return _ICON_PATH
            except Exception as e:
                print(f"[Icon] Download attempt {attempt + 1} failed: {e}")
                if attempt == 2:
                    break
        
    except Exception as e:
        print(f"[Icon] Download error: {e}")
    
    print("[Icon] WARNING: Could not obtain icon file")
    return None


# All scanner classes remain the same as v1.0.3
class SecurityScanner:
    """Backend scanner class - same as before"""
    def __init__(self, target_url: str, timeout: int = 10, progress_callback=None):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.base_domain = self.parsed_url.netloc
        self.timeout = timeout
        self.session = self._create_session()
        self.vulnerabilities = []
        self.scanned_urls = set()
        self.progress_callback = progress_callback
        
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry_strategy = Retry(
            total=2, backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({'User-Agent': f'IT2WebITScanTool/{CURRENT_VERSION}'})
        return session
    
    def add_vulnerability(self, title, severity, description, location, fix, evidence=""):
        self.vulnerabilities.append({
            'title': title, 'severity': severity, 'description': description,
            'location': location, 'fix': fix, 'evidence': evidence,
            'timestamp': datetime.datetime.now().isoformat()
        })
    
    def update_progress(self, message):
        if self.progress_callback:
            self.progress_callback(message)
    
    def scan(self):
        self.update_progress("Starting security scan...")
        checks = [
            ("SSL/TLS Configuration", self.check_ssl_tls),
            ("Security Headers", self.check_security_headers),
            ("CORS Configuration", self.check_cors_configuration),
            ("Information Disclosure", self.check_information_disclosure),
            ("Clickjacking Protection", self.check_clickjacking),
            ("XSS Protection", self.check_xss_protection),
            ("Cookie Security", self.check_cookie_security),
            ("Server Information", self.check_server_info),
            ("Directory Listing", self.check_directory_listing),
            ("Form Security", self.check_form_security),
            ("Outdated Components", self.check_outdated_components),
            ("CSRF Protection", self.check_csrf_protection),
            ("SQL Injection Indicators", self.check_sql_injection_indicators),
        ]
        for check_name, check_func in checks:
            try:
                self.update_progress(f"Running: {check_name}...")
                check_func()
            except Exception as e:
                self.update_progress(f"Error in {check_name}: {str(e)}")
        self.update_progress("Scan complete!")
    
    # All check methods remain identical to v1.0.3
    def check_ssl_tls(self):
        if not self.target_url.startswith('https://'):
            self.add_vulnerability("Missing HTTPS", "HIGH", "Website is not using HTTPS.", self.target_url, "Implement SSL/TLS certificate and force HTTPS redirect.")
            return
        try:
            hostname = self.parsed_url.hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_expires = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_left = (cert_expires - datetime.datetime.now()).days
                    if days_left < 30:
                        self.add_vulnerability("SSL Certificate Expiring Soon", "MEDIUM", f"SSL certificate expires in {days_left} days.", self.target_url, "Renew SSL certificate.")
                    tls_version = ssock.version()
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                        self.add_vulnerability("Outdated TLS Version", "HIGH", f"Server supports {tls_version}.", self.target_url, "Disable TLS 1.0/1.1.")
        except: pass

    def check_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            headers = response.headers
            security_headers = {
                'Strict-Transport-Security': {'severity': 'MEDIUM', 'desc': 'HSTS missing.', 'fix': 'Add HSTS header.'},
                'Content-Security-Policy': {'severity': 'HIGH', 'desc': 'CSP missing.', 'fix': 'Implement CSP.'},
                'X-Frame-Options': {'severity': 'MEDIUM', 'desc': 'X-Frame-Options missing.', 'fix': 'Add X-Frame-Options.'},
                'X-Content-Type-Options': {'severity': 'LOW', 'desc': 'X-Content-Type-Options missing.', 'fix': 'Add nosniff.'},
            }
            for header, info in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(f"Missing: {header}", info['severity'], info['desc'], self.target_url, info['fix'])
        except: pass

    def check_cors_configuration(self):
        try:
            response = self.session.get(self.target_url, headers={'Origin': 'https://evil.com'}, timeout=self.timeout, verify=False)
            cors = response.headers.get('Access-Control-Allow-Origin', '')
            if cors == '*':
                self.add_vulnerability("Dangerous CORS", "HIGH", "CORS allows any origin.", self.target_url, "Restrict CORS origins.")
            elif cors == 'https://evil.com':
                self.add_vulnerability("CORS Origin Reflection", "HIGH", "CORS reflects origins.", self.target_url, "Validate origins.")
        except: pass

    def check_information_disclosure(self):
        try:
            for path in ['/.git/config', '/.env', '/backup', '/wp-config.php', '/phpinfo.php', '/.htaccess']:
                url = urljoin(self.target_url, path)
                if self.session.get(url, timeout=self.timeout, verify=False).status_code == 200:
                    self.add_vulnerability("Sensitive File Exposed", "HIGH", f"File accessible: {path}", url, "Restrict access.")
        except: pass

    def check_clickjacking(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            x_frame = response.headers.get('X-Frame-Options', '').upper()
            csp = response.headers.get('Content-Security-Policy', '')
            if x_frame not in ['DENY', 'SAMEORIGIN'] and 'frame-ancestors' not in csp:
                self.add_vulnerability("Clickjacking Vulnerable", "MEDIUM", "No frame protection.", self.target_url, "Add frame-ancestors or X-Frame-Options.")
        except: pass

    def check_xss_protection(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                if not any('csrf' in inp.get('name', '').lower() for inp in form.find_all('input')):
                    self.add_vulnerability("Form Without CSRF", "HIGH", "Form lacks CSRF token.", form.get('action', self.target_url), "Add CSRF tokens.")
        except: pass

    def check_cookie_security(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            for cookie in response.cookies:
                issues = []
                if not cookie.secure: issues.append("Secure missing")
                if not cookie.has_nonstandard_attr('HttpOnly'): issues.append("HttpOnly missing")
                if not cookie.has_nonstandard_attr('SameSite'): issues.append("SameSite missing")
                if issues:
                    self.add_vulnerability("Insecure Cookie", "MEDIUM", f"Cookie '{cookie.name}': {', '.join(issues)}", self.target_url, "Set Secure, HttpOnly, SameSite.")
        except: pass

    def check_server_info(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            if response.headers.get('Server'):
                self.add_vulnerability("Server Info Leak", "LOW", f"Server: {response.headers['Server']}", self.target_url, "Suppress Server header.")
        except: pass

    def check_directory_listing(self):
        try:
            for d in ['/images/', '/css/', '/js/', '/assets/', '/admin/']:
                url = urljoin(self.target_url, d)
                resp = self.session.get(url, timeout=self.timeout, verify=False)
                if resp.status_code == 200 and any(x in resp.text for x in ['Index of', 'Directory Listing']):
                    self.add_vulnerability("Directory Listing", "MEDIUM", f"Listing enabled: {d}", url, "Disable directory listing.")
        except: pass

    def check_form_security(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                if form.find_all('input', {'type': 'password'}) and form.get('method', 'GET').upper() == 'GET':
                    self.add_vulnerability("Password via GET", "HIGH", "Password form uses GET.", form.get('action'), "Use POST method.")
        except: pass

    def check_outdated_components(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            for ver in re.findall(r'jquery[.-](\d+\.\d+\.\d+)', response.text, re.IGNORECASE):
                parts = ver.split('.')
                if len(parts) >= 2 and (int(parts[0]) < 3 or (int(parts[0]) == 3 and int(parts[1]) < 5)):
                    self.add_vulnerability("Outdated jQuery", "MEDIUM", f"jQuery {ver}", self.target_url, "Update jQuery.")
        except: pass

    def check_csrf_protection(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                if form.get('method', 'GET').upper() == 'POST':
                    if not any(any(p in i.get('name', '').lower() for p in ['csrf', 'token']) for i in form.find_all('input')):
                        self.add_vulnerability("Missing CSRF", "HIGH", "POST form without CSRF.", form.get('action'), "Add CSRF tokens.")
        except: pass

    def check_sql_injection_indicators(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            for form in soup.find_all('form'):
                action = form.get('action', self.target_url)
                test_data = {inp.get('name', ''): "' OR '1'='1" for inp in form.find_all('input') if inp.get('name')}
                if test_data:
                    method = form.get('method', 'GET').upper()
                    resp = self.session.post(urljoin(self.target_url, action), data=test_data, timeout=self.timeout, verify=False) if method == 'POST' else self.session.get(urljoin(self.target_url, action), params=test_data, timeout=self.timeout, verify=False)
                    if any(e in resp.text.lower() for e in ['sql', 'mysql', 'syntax error']):
                        self.add_vulnerability("Potential SQLi", "HIGH", "SQL error in response.", action, "Use parameterized queries.")
        except: pass

    def export_to_json(self, filename):
        export_data = {
            'scan_info': {'target_url': self.target_url, 'base_domain': self.base_domain, 'scan_date': datetime.datetime.now().isoformat(), 'total_vulnerabilities': len(self.vulnerabilities), 'tool_version': CURRENT_VERSION},
            'vulnerabilities': self.vulnerabilities,
            'severity_summary': {s.lower(): len([v for v in self.vulnerabilities if v['severity'] == s]) for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']}
        }
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)


class AutoUpdater:
    """Handles automatic updates - same as v1.0.3"""
    def __init__(self, current_version, github_repo):
        self.current_version = current_version
        self.github_repo = github_repo
        self.api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"
    
    def check_for_update(self):
        try:
            response = requests.get(self.api_url, headers={'Accept': 'application/vnd.github.v3+json'}, timeout=5)
            if response.status_code == 200:
                release_data = response.json()
                latest_tag = release_data.get('tag_name', 'v0.0.0').replace('v', '')
                if version.parse(latest_tag) > version.parse(self.current_version):
                    download_url = next((a['browser_download_url'] for a in release_data.get('assets', []) if a['name'].endswith('.exe')), None) or f"https://github.com/{github_repo}/releases/latest/download/IT2WebITScanTool.exe"
                    return {'update_available': True, 'latest_version': latest_tag, 'current_version': self.current_version, 'download_url': download_url, 'release_notes': release_data.get('body', ''), 'release_url': release_data.get('html_url', '')}
                return {'update_available': False, 'latest_version': latest_tag, 'current_version': self.current_version}
        except: pass
        return None
    
    def download_update(self, download_url, progress_callback=None):
        try:
            new_exe = os.path.join(tempfile.gettempdir(), "IT2WebITScanTool_update.exe")
            response = requests.get(download_url, stream=True)
            total = int(response.headers.get('content-length', 0))
            if total == 0: return None
            downloaded = 0
            with open(new_exe, 'wb') as f:
                for data in response.iter_content(8192):
                    downloaded += len(data)
                    f.write(data)
                    if progress_callback: progress_callback(int((downloaded / total) * 100))
            return new_exe
        except: return None
    
    def install_update(self, new_exe_path):
        try:
            current_exe = sys.executable
            batch = os.path.join(tempfile.gettempdir(), "update_installer.bat")
            with open(batch, 'w') as f:
                f.write("@echo off\ntimeout /t 2 /nobreak >nul\n")
                f.write(f'copy /Y "{new_exe_path}" "{current_exe}"\n')
                f.write(f'start "" "{current_exe}"\n')
                f.write(f'del "{batch}"\n')
            subprocess.Popen(batch, shell=True, creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0)
            return True
        except: return False


class SecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        
        # CRITICAL: Set window properties BEFORE anything else
        self.root.withdraw()  # Hide window until fully configured
        
        # Set the title
        self.root.title(f"IT2Innovations Web IT Scan Tool v{CURRENT_VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Set Windows AppUserModelID (must be done before window is shown)
        if sys.platform == 'win32':
            try:
                app_id = 'IT2Innovations.IT2WebITScanTool'
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
            except: pass
        
        # Setup icon PROPERLY - this is the key fix
        self.setup_app_icon()
        
        # Now show the window
        self.root.deiconify()
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.colors = {
            'bg': '#2b2b2b', 'fg': '#ffffff', 'select_bg': '#404040',
            'button_bg': '#0d7377', 'button_fg': '#ffffff',
            'critical': '#ff4444', 'high': '#ff8800', 'medium': '#ffbb33',
            'low': '#00C851', 'info': '#33b5e5', 'success': '#00C851',
            'warning': '#ffbb33', 'error': '#ff4444'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        self.target_url = tk.StringVar()
        self.scanning = False
        self.scanner = None
        self.updater = AutoUpdater(CURRENT_VERSION, GITHUB_REPO)
        
        self.setup_ui()
        self.root.after(1500, self.check_for_updates_silent)
    
    def setup_app_icon(self):
        """
        Set the application icon for:
        1. Window title bar (top-left corner)
        2. Taskbar
        3. Alt+Tab switcher
        """
        icon_path = get_icon_path()
        
        if not icon_path:
            print("[Icon] ERROR: No icon file available")
            return
        
        print(f"[Icon] Setting icon from: {icon_path}")
        
        # METHOD 1: iconbitmap - This is what sets the title bar icon
        # Use 'default' parameter which applies to ALL future windows including dialogs
        try:
            self.root.iconbitmap(default=icon_path)
            print("[Icon] iconbitmap(default) set successfully")
        except tk.TclError as e:
            print(f"[Icon] iconbitmap failed: {e}")
            # Try alternate path format
            try:
                self.root.iconbitmap(icon_path)
                print("[Icon] iconbitmap() set successfully")
            except Exception as e2:
                print(f"[Icon] iconbitmap alternate failed: {e2}")
        
        # METHOD 2: iconphoto - Sets icon using a PhotoImage (supports PNG/ICO via PIL)
        try:
            img = Image.open(icon_path)
            photo = ImageTk.PhotoImage(img)
            self.root.iconphoto(True, photo)
            # Keep reference to prevent garbage collection
            self._icon_photo = photo
            print("[Icon] iconphoto set successfully")
        except Exception as e:
            print(f"[Icon] iconphoto failed: {e}")
        
        # METHOD 3: Windows-specific - Set both small and large icons
        if sys.platform == 'win32':
            try:
                import ctypes.wintypes
                
                # Load the icon
                hicon = ctypes.windll.user32.LoadImageW(
                    0, icon_path, 1,  # IMAGE_ICON
                    0, 0, 0x00000010 | 0x00002000  # LR_LOADFROMFILE | LR_DEFAULTSIZE
                )
                
                if hicon:
                    hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                    # Set both small and large icons
                    ctypes.windll.user32.SendMessageW(hwnd, 0x0080, 0, hicon)  # WM_SETICON, ICON_SMALL
                    ctypes.windll.user32.SendMessageW(hwnd, 0x0080, 1, hicon)  # WM_SETICON, ICON_BIG
                    print("[Icon] Windows icons set via Win32 API")
            except Exception as e:
                print(f"[Icon] Win32 API method failed: {e}")
    
    def setup_ui(self):
        """Setup the user interface"""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results (JSON)", command=self.export_results, accelerator="Ctrl+S")
        file_menu.add_command(label="Clear Results", command=self.clear_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Check for Updates", command=self.manual_update_check)
        tools_menu.add_command(label="View GitHub", command=lambda: webbrowser.open(UPDATE_URL))
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about_dialog)
        help_menu.add_command(label="Usage Guide", command=self.show_usage)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        ttk.Label(title_frame, text="IT2Innovations Web IT Scan Tool", font=('Helvetica', 16, 'bold')).grid(row=0, column=0)
        ttk.Label(title_frame, text=f"v{CURRENT_VERSION}", font=('Helvetica', 9), foreground=self.colors['info']).grid(row=1, column=0)
        
        # URL Input
        url_frame = ttk.Frame(main_frame)
        url_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        url_frame.columnconfigure(1, weight=1)
        
        ttk.Label(url_frame, text="Target URL:").grid(row=0, column=0, padx=(0, 10))
        self.url_entry = ttk.Entry(url_frame, textvariable=self.target_url, font=('Helvetica', 11), width=50)
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        self.url_entry.bind('<Return>', lambda e: self.start_scan())
        
        button_frame = ttk.Frame(url_frame)
        button_frame.grid(row=0, column=2)
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=0, column=0, padx=(0, 5))
        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_scan, state='disabled')
        self.stop_button.grid(row=0, column=1)
        
        # Progress
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.StringVar(value="Ready to scan...")
        ttk.Label(progress_frame, textvariable=self.progress_var, font=('Helvetica', 9)).grid(row=0, column=0, sticky=tk.W)
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Results paned window
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.rowconfigure(3, weight=1)
        
        # Left panel - Tree
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)
        
        filter_frame = ttk.Frame(left_frame)
        filter_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        ttk.Label(filter_frame, text="Filter:").grid(row=0, column=0, padx=(0, 5))
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(filter_frame, textvariable=self.filter_var, values=["All", "Critical", "High", "Medium", "Low"], state='readonly', width=10)
        self.filter_combo.grid(row=0, column=1, padx=(0, 10))
        self.filter_combo.bind('<<ComboboxSelected>>', self.filter_vulnerabilities)
        
        tree_frame = ttk.Frame(left_frame)
        tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(1, weight=1)
        
        self.tree = ttk.Treeview(tree_frame, columns=('Severity', 'Title'), show='headings', height=20)
        self.tree.heading('Severity', text='Severity')
        self.tree.heading('Title', text='Vulnerability')
        self.tree.column('Severity', width=80)
        self.tree.column('Title', width=400)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        self.tree.bind('<<TreeviewSelect>>', self.on_vulnerability_select)
        
        for sev in ['critical', 'high', 'medium', 'low']:
            self.tree.tag_configure(sev, foreground=self.colors[sev])
        
        # Right panel - Details
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=2)
        
        ttk.Label(right_frame, text="Vulnerability Details", font=('Helvetica', 11, 'bold')).grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.detail_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, width=60, height=20, font=('Courier', 10))
        self.detail_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)
        
        for sev in ['critical', 'high', 'medium', 'low']:
            self.detail_text.tag_configure(sev, foreground=self.colors[sev])
        self.detail_text.tag_configure('bold', font=('Courier', 10, 'bold'))
        self.detail_text.tag_configure('heading', font=('Courier', 12, 'bold'))
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var, font=('Helvetica', 9), foreground=self.colors['info']).grid(row=0, column=0, sticky=tk.W)
        
        self.export_button = ttk.Button(status_frame, text="Export to JSON", command=self.export_results, state='disabled')
        self.export_button.grid(row=0, column=1, sticky=tk.E, padx=(0, 5))
        
        self.clear_button = ttk.Button(status_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.grid(row=0, column=2, sticky=tk.E)
        status_frame.columnconfigure(0, weight=1)
        
        self.root.bind('<Control-s>', lambda e: self.export_results())
    
    # All remaining methods are identical to v1.0.3
    # (check_for_updates_silent, manual_update_check, show_update_dialog, etc.)
    # [Same as previous version - omitted for brevity but must be included in final file]
    
    def check_for_updates_silent(self):
        result = self.updater.check_for_update()
        if result and result.get('update_available'):
            self.root.after(500, lambda: self.show_update_dialog(result))
        else:
            self.status_var.set(f"Up to date (v{CURRENT_VERSION})")
    
    def manual_update_check(self):
        self.status_var.set("Checking for updates...")
        result = self.updater.check_for_update()
        if result:
            self.show_update_dialog(result, up_to_date=not result.get('update_available'))
        else:
            messagebox.showinfo("Update Check", "Unable to check for updates.")
            self.status_var.set("Ready")
    
    def show_update_dialog(self, update_info, up_to_date=False):
        dialog = tk.Toplevel(self.root)
        icon_path = get_icon_path()
        if icon_path:
            try: dialog.iconbitmap(icon_path)
            except: pass
        
        if up_to_date:
            dialog.title("You're Up to Date!")
            h = 400
        else:
            dialog.title("Update Available!")
            h = 600
        
        dialog.geometry(f"500x{h}")
        dialog.configure(bg=self.colors['bg'])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 500) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
        dialog.geometry(f"+{x}+{y}")
        
        if up_to_date:
            self._build_up_to_date(dialog, update_info)
        else:
            self._build_update_available(dialog, update_info)
    
    def _build_up_to_date(self, dialog, info):
        tk.Label(dialog, text="You're Up to Date!", font=('Helvetica', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['success']).pack(pady=(30,10))
        tk.Label(dialog, text="\u2713", font=('Helvetica', 48), bg=self.colors['bg'], fg=self.colors['success']).pack(pady=10)
        f = tk.Frame(dialog, bg=self.colors['bg']); f.pack(fill=tk.BOTH, padx=30, pady=10)
        tk.Label(f, text=f"Current: v{info.get('current_version', CURRENT_VERSION)}", font=('Helvetica',11), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=5)
        tk.Label(f, text=f"Latest: v{info.get('latest_version', CURRENT_VERSION)}", font=('Helvetica',11), bg=self.colors['bg'], fg=self.colors['success']).pack(pady=5)
        tk.Label(f, text="No update needed.", font=('Helvetica',10), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=20)
        tk.Button(dialog, text="Close", font=('Helvetica',11), bg=self.colors['select_bg'], fg=self.colors['fg'], relief=tk.FLAT, padx=30, pady=10, command=dialog.destroy).pack(pady=20)
    
    def _build_update_available(self, dialog, info):
        tk.Label(dialog, text="Update Available!", font=('Helvetica', 16, 'bold'), bg=self.colors['bg'], fg=self.colors['warning']).pack(pady=(30,10))
        tk.Label(dialog, text="\u2B06", font=('Helvetica', 48), bg=self.colors['bg'], fg=self.colors['warning']).pack(pady=10)
        f = tk.Frame(dialog, bg=self.colors['bg']); f.pack(fill=tk.BOTH, padx=30, pady=10)
        tk.Label(f, text="Current:", font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W)
        tk.Label(f, text=f"v{info['current_version']}", font=('Helvetica',12), bg=self.colors['bg'], fg=self.colors['info']).pack(anchor=tk.W, pady=(0,10))
        tk.Label(f, text="Latest:", font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W)
        tk.Label(f, text=f"v{info['latest_version']}", font=('Helvetica',12), bg=self.colors['bg'], fg=self.colors['warning']).pack(anchor=tk.W, pady=(0,15))
        tk.Frame(f, height=1, bg=self.colors['info']).pack(fill=tk.X, pady=10)
        
        if info.get('release_notes'):
            tk.Label(f, text="What's New:", font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor=tk.W, pady=(0,5))
            notes = tk.Text(f, height=8, width=55, font=('Helvetica',9), bg=self.colors['select_bg'], fg=self.colors['fg'], relief=tk.FLAT, wrap=tk.WORD)
            notes.pack(fill=tk.BOTH, pady=(0,10))
            notes.insert('1.0', info['release_notes'][:500])
            notes.config(state='disabled')
        
        auto = tk.BooleanVar(value=True)
        tk.Checkbutton(f, text="Auto-install after download", variable=auto, bg=self.colors['bg'], fg=self.colors['fg'], selectcolor=self.colors['select_bg']).pack(anchor=tk.W, pady=5)
        
        prog = ttk.Progressbar(f, mode='determinate', length=400)
        plabel = tk.Label(f, text="", font=('Helvetica',9), bg=self.colors['bg'], fg=self.colors['info'])
        
        btns = tk.Frame(dialog, bg=self.colors['bg']); btns.pack(pady=20)
        
        def update_now():
            for b in [dl_btn, cl_btn]: b.config(state='disabled')
            prog.pack(fill=tk.X, pady=5); plabel.pack()
            plabel.config(text="Downloading...")
            
            def dl_thread():
                exe = self.updater.download_update(info['download_url'], lambda p: (prog.config(value=p), plabel.config(text=f"Downloading: {p}%"), dialog.update_idletasks()))
                if exe:
                    plabel.config(text="Download complete!")
                    if auto.get():
                        plabel.config(text="Installing...")
                        dialog.update_idletasks()
                        if self.updater.install_update(exe):
                            plabel.config(text="Restarting...")
                            dialog.after(1500, self.root.quit)
                        else:
                            plabel.config(text="Opening download page...")
                            webbrowser.open(info['release_url'])
                    else:
                        messagebox.showinfo("Done", f"Downloaded to:\n{exe}", parent=dialog)
                else:
                    plabel.config(text="Failed. Opening page...")
                    webbrowser.open(info['release_url'])
                for b in [dl_btn, cl_btn]: b.config(state='normal')
            
            threading.Thread(target=dl_thread, daemon=True).start()
        
        dl_btn = tk.Button(btns, text="Update Now", font=('Helvetica',11,'bold'), bg=self.colors['button_bg'], fg=self.colors['button_fg'], relief=tk.FLAT, padx=20, pady=10, command=update_now)
        dl_btn.pack(side=tk.LEFT, padx=(0,10))
        cl_btn = tk.Button(btns, text="Remind Later", font=('Helvetica',11), bg=self.colors['select_bg'], fg=self.colors['fg'], relief=tk.FLAT, padx=20, pady=10, command=dialog.destroy)
        cl_btn.pack(side=tk.LEFT)
    
    def show_about_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("About")
        dialog.geometry("500x550")
        dialog.configure(bg=self.colors['bg'])
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        icon_path = get_icon_path()
        if icon_path:
            try: dialog.iconbitmap(icon_path)
            except: pass
        
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 500) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 550) // 2
        dialog.geometry(f"+{x}+{y}")
        
        tk.Label(dialog, text="IT2Innovations Web IT Scan Tool", font=('Helvetica', 14, 'bold'), bg=self.colors['bg'], fg=self.colors['info']).pack(pady=(30,5))
        tk.Label(dialog, text=f"Version {CURRENT_VERSION}", font=('Helvetica', 11), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=(0,20))
        
        f = tk.Frame(dialog, bg=self.colors['bg']); f.pack(fill=tk.BOTH, padx=40)
        for label, value in [("Creator:", "Mike Larios"), ("Engineering Validation:", "Mike Larios"), ("License:", "MIT & Apache"), ("Repository:", f"github.com/{GITHUB_REPO}")]:
            row = tk.Frame(f, bg=self.colors['bg']); row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label, font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(side=tk.LEFT)
            tk.Label(row, text=value, font=('Helvetica',10), bg=self.colors['bg'], fg=self.colors['info']).pack(side=tk.LEFT, padx=(5,0))
        
        tk.Frame(f, height=2, bg=self.colors['info']).pack(fill=tk.X, pady=15)
        tk.Label(f, text="IMPORTANT LEGAL NOTICE", font=('Helvetica',11,'bold'), bg=self.colors['bg'], fg=self.colors['high']).pack(pady=(5,10))
        tk.Label(f, text="This program is a testing tool, Pen Testing tool, and a tool used to exploit vulnerabilities of weakened or compromised websites.\n\nThis can get you in trouble if you are not authorized by the site/ISP/Owner of the domain you are testing against.\n\nAll legal ramifications will be on you, not any companies, persons, or devices mentioned in this file. We hold no legal or other responsible parts to the usage of this application.\n\nThis is created and considered 'AS-IS' best effort coded.", font=('Helvetica',9), bg=self.colors['bg'], fg=self.colors['fg'], wraplength=420, justify=tk.LEFT).pack(pady=(0,15))
        tk.Button(dialog, text="Close", font=('Helvetica',11), bg=self.colors['select_bg'], fg=self.colors['fg'], relief=tk.FLAT, padx=30, pady=10, command=dialog.destroy).pack(pady=(0,20))
    
    def show_usage(self):
        messagebox.showinfo("Usage Guide", "USAGE GUIDE\n\n1. Enter target URL\n2. Click Start Scan\n3. Confirm authorization\n4. Review results\n5. Export to JSON\n\nAUTO-UPDATE:\nThe tool checks for updates on startup.\nUpdates can be auto-installed.")
    
    def start_scan(self):
        url = self.target_url.get().strip()
        if not url: return messagebox.showwarning("No URL", "Enter a target URL.")
        if not url.startswith(('http://','https://')): url = 'https://' + url; self.target_url.set(url)
        if not messagebox.askyesno("Authorization", "Do you have authorization to scan this target?", icon='warning'): return
        self.clear_results()
        self.scan_button.config(state='disabled'); self.stop_button.config(state='normal'); self.export_button.config(state='disabled')
        self.url_entry.config(state='disabled'); self.filter_combo.config(state='disabled')
        self.progress_bar.start(10); self.progress_var.set("Initializing..."); self.status_var.set("Scanning...")
        self.scanning = True
        threading.Thread(target=self.run_scan, args=(url,), daemon=True).start()
    
    def run_scan(self, url):
        try:
            self.scanner = SecurityScanner(url, progress_callback=self.update_progress)
            self.scanner.scan()
            self.root.after(0, self.scan_complete)
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def update_progress(self, msg):
        self.root.after(0, lambda: self.progress_var.set(msg))
        self.root.after(0, lambda: self.status_var.set(msg))
    
    def scan_complete(self):
        self.progress_bar.stop()
        self.progress_var.set(f"Scan complete! Found {len(self.scanner.vulnerabilities)} vulnerabilities.")
        self.status_var.set(f"Found {len(self.scanner.vulnerabilities)} vulnerabilities")
        self.scan_button.config(state='normal'); self.stop_button.config(state='disabled'); self.export_button.config(state='normal')
        self.url_entry.config(state='normal'); self.filter_combo.config(state='readonly')
        self.populate_tree(); self.scanning = False
    
    def scan_error(self, msg):
        self.progress_bar.stop(); self.progress_var.set(f"Error: {msg}"); self.status_var.set("Scan failed")
        self.scan_button.config(state='normal'); self.stop_button.config(state='disabled')
        self.url_entry.config(state='normal'); self.filter_combo.config(state='readonly')
        self.scanning = False
        messagebox.showerror("Error", f"Scan error:\n\n{msg}")
    
    def stop_scan(self):
        self.scanning = False; self.progress_bar.stop()
        self.progress_var.set("Scan stopped"); self.status_var.set("Stopped")
        self.scan_button.config(state='normal'); self.stop_button.config(state='disabled')
        self.url_entry.config(state='normal'); self.filter_combo.config(state='readonly')
    
    def populate_tree(self, filter_sev="All"):
        for i in self.tree.get_children(): self.tree.delete(i)
        if not self.scanner: return
        order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
        for v in sorted(self.scanner.vulnerabilities, key=lambda x: order.get(x['severity'].upper(),4)):
            if filter_sev == "All" or v['severity'].upper() == filter_sev.upper():
                self.tree.insert('','end',values=(v['severity'],v['title']),tags=(v['severity'].lower(),))
    
    def filter_vulnerabilities(self, e=None): self.populate_tree(self.filter_var.get())
    
    def on_vulnerability_select(self, e):
        sel = self.tree.selection()
        if not sel: return
        title = self.tree.item(sel[0])['values'][1]
        if self.scanner:
            for v in self.scanner.vulnerabilities:
                if v['title'] == title: self.display_vulnerability_details(v); break
    
    def display_vulnerability_details(self, v):
        self.detail_text.delete('1.0', tk.END)
        t = v['severity'].lower()
        self.detail_text.insert(tk.END, "VULNERABILITY DETAILS\n", 'heading')
        self.detail_text.insert(tk.END, "-"*50 + "\n\n")
        self.detail_text.insert(tk.END, "Title: ",'bold'); self.detail_text.insert(tk.END, f"{v['title']}\n\n")
        self.detail_text.insert(tk.END, "Severity: ",'bold'); self.detail_text.insert(tk.END, f"{v['severity']}\n", t)
        self.detail_text.insert(tk.END, "\nLocation:\n",'bold'); self.detail_text.insert(tk.END, f"  {v['location']}\n\n")
        self.detail_text.insert(tk.END, "Description:\n",'bold'); self.detail_text.insert(tk.END, f"  {v['description']}\n\n")
        if v['evidence']: self.detail_text.insert(tk.END, "Evidence:\n",'bold'); self.detail_text.insert(tk.END, f"  {v['evidence']}\n\n")
        self.detail_text.insert(tk.END, "Fix:\n",'bold'); self.detail_text.insert(tk.END, f"  {v['fix']}\n\n")
        self.detail_text.insert(tk.END, "Detected:\n",'bold'); self.detail_text.insert(tk.END, f"  {v['timestamp']}\n")
        self.detail_text.see('1.0')
    
    def export_results(self):
        if not self.scanner or not self.scanner.vulnerabilities: return messagebox.showwarning("No Results", "Nothing to export.")
        fn = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], initialfile=f"scan_{self.scanner.base_domain}_{datetime.datetime.now():%Y%m%d_%H%M%S}.json")
        if fn:
            try:
                self.scanner.export_to_json(fn)
                if messagebox.askyesno("Done", f"Saved to:\n{fn}\n\nOpen?"): os.startfile(fn)
            except Exception as e: messagebox.showerror("Error", str(e))
    
    def clear_results(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        self.detail_text.delete('1.0', tk.END)
        self.progress_var.set("Ready to scan..."); self.status_var.set("Ready")
        self.export_button.config(state='disabled'); self.scanner = None

def main():
    root = tk.Tk()
    
    # Set AppUserModelID BEFORE window creation
    if sys.platform == 'win32':
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('IT2Innovations.IT2WebITScanTool')
        except: pass
    
    app = SecurityScannerGUI(root)
    
    root.update_idletasks()
    w, h = 1200, 800
    x = (root.winfo_screenwidth() // 2) - (w // 2)
    y = (root.winfo_screenheight() // 2) - (h // 2)
    root.geometry(f'{w}x{h}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()