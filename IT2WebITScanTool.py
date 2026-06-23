#!/usr/bin/env python3
"""
IT2Innovations Web IT Scan Tool v1.0.6
For educational and authorized security testing purposes only.

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
import shutil
import winreg

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Version
CURRENT_VERSION = "1.0.6"
GITHUB_REPO = "someguru/IT2WebITScanTool"
UPDATE_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"

_ICON_PATH = None

def resource_path(relative_path):
    """Get absolute path to resource, works for dev and PyInstaller"""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_path, relative_path)

def get_icon_path():
    """Get icon path with multiple fallbacks"""
    global _ICON_PATH
    
    if _ICON_PATH and os.path.exists(_ICON_PATH):
        return _ICON_PATH
    
    # Check bundled path first (PyInstaller)
    if getattr(sys, 'frozen', False):
        bundled = resource_path('it2_icon.ico')
        if os.path.exists(bundled):
            _ICON_PATH = bundled
            return _ICON_PATH
    
    # Check script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    local = os.path.join(script_dir, 'it2_icon.ico')
    if os.path.exists(local):
        _ICON_PATH = local
        return _ICON_PATH
    
    # Check temp directory
    temp = os.path.join(tempfile.gettempdir(), 'it2_icon.ico')
    if os.path.exists(temp):
        _ICON_PATH = temp
        return _ICON_PATH
    
    # Download
    try:
        urllib.request.urlretrieve(
            "http://www.it2innovations.com/images/favicon.ico",
            temp
        )
        if os.path.exists(temp):
            _ICON_PATH = temp
            return _ICON_PATH
    except:
        pass
    
    return None

def set_window_icon(hwnd, icon_path):
    """Set window icon using native Windows API - this ALWAYS works"""
    if not sys.platform == 'win32':
        return False
    
    try:
        # Load the icon from file
        hicon = ctypes.windll.user32.LoadImageW(
            0, icon_path, 1,  # IMAGE_ICON
            0, 0,
            0x00000010 | 0x00002000  # LR_LOADFROMFILE | LR_DEFAULTSIZE
        )
        
        if not hicon:
            # Try loading as small icon
            hicon = ctypes.windll.user32.LoadImageW(
                0, icon_path, 1,
                16, 16,  # Small icon
                0x00000010  # LR_LOADFROMFILE
            )
        
        if hicon:
            # WM_SETICON: 0x0080
            # ICON_SMALL: 0, ICON_BIG: 1
            ctypes.windll.user32.SendMessageW(hwnd, 0x0080, 0, hicon)  # Small icon (title bar)
            ctypes.windll.user32.SendMessageW(hwnd, 0x0080, 1, hicon)  # Big icon (alt+tab)
            return True
    except Exception as e:
        print(f"Win32 icon error: {e}")
    
    return False

def check_internet_connection():
    """Check if internet is available"""
    try:
        # Try multiple URLs for redundancy
        urls = [
            'https://github.com',
            'https://google.com',
            'https://cloudflare.com'
        ]
        for url in urls:
            try:
                response = requests.head(url, timeout=3)
                if response.status_code < 500:
                    return True
            except:
                continue
        return False
    except:
        return False

def install_application():
    """Install the application to Program Files and create shortcuts"""
    if not sys.platform == 'win32':
        return False
    
    try:
        current_exe = sys.executable
        
        # Installation directory
        install_dir = os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 'IT2Innovations', 'IT2WebITScanTool')
        os.makedirs(install_dir, exist_ok=True)
        
        # Copy executable
        target_exe = os.path.join(install_dir, 'IT2WebITScanTool.exe')
        shutil.copy2(current_exe, target_exe)
        
        # Copy icon if available
        icon_path = get_icon_path()
        if icon_path:
            target_icon = os.path.join(install_dir, 'it2_icon.ico')
            shutil.copy2(icon_path, target_icon)
        else:
            target_icon = target_exe  # Use exe's embedded icon
        
        # Create Start Menu shortcut
        start_menu = os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 
                                   'Microsoft\\Windows\\Start Menu\\Programs\\IT2Innovations')
        os.makedirs(start_menu, exist_ok=True)
        
        shortcut_path = os.path.join(start_menu, 'IT2WebITScanTool.lnk')
        create_shortcut(target_exe, shortcut_path, target_icon, "IT2Innovations Web IT Scan Tool")
        
        # Create Desktop shortcut
        desktop = os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop')
        desktop_shortcut = os.path.join(desktop, 'IT2WebITScanTool.lnk')
        create_shortcut(target_exe, desktop_shortcut, target_icon, "IT2Innovations Web IT Scan Tool")
        
        # Add to registry for uninstall
        add_to_uninstall_list(target_exe, install_dir)
        
        # Launch the installed version
        subprocess.Popen([target_exe])
        
        return True
        
    except Exception as e:
        print(f"Installation failed: {e}")
        return False

def create_shortcut(target, shortcut_path, icon_path, description):
    """Create Windows shortcut"""
    try:
        import pythoncom
        from win32com.client import Dispatch
        
        pythoncom.CoInitialize()
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.WorkingDirectory = os.path.dirname(target)
        shortcut.IconLocation = icon_path if icon_path else target
        shortcut.Description = description
        shortcut.save()
        pythoncom.CoUninitialize()
        return True
    except:
        # Fallback: use PowerShell
        try:
            ps_command = (
                f'$ws = New-Object -ComObject WScript.Shell; '
                f'$s = $ws.CreateShortcut("{shortcut_path}"); '
                f'$s.TargetPath = "{target}"; '
                f'$s.WorkingDirectory = "{os.path.dirname(target)}"; '
                f'$s.IconLocation = "{icon_path}"; '
                f'$s.Description = "{description}"; '
                f'$s.Save()'
            )
            subprocess.run(['powershell', '-Command', ps_command], capture_output=True, shell=True)
            return os.path.exists(shortcut_path)
        except:
            return False

def add_to_uninstall_list(exe_path, install_dir):
    """Add application to Windows uninstall list"""
    try:
        key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IT2WebITScanTool"
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        
        winreg.SetValueEx(key, "DisplayName", 0, winreg.REG_SZ, "IT2Innovations Web IT Scan Tool")
        winreg.SetValueEx(key, "DisplayVersion", 0, winreg.REG_SZ, CURRENT_VERSION)
        winreg.SetValueEx(key, "Publisher", 0, winreg.REG_SZ, "Mike Larios")
        winreg.SetValueEx(key, "DisplayIcon", 0, winreg.REG_SZ, exe_path)
        winreg.SetValueEx(key, "InstallLocation", 0, winreg.REG_SZ, install_dir)
        winreg.SetValueEx(key, "UninstallString", 0, winreg.REG_SZ, f'"{exe_path}" --uninstall')
        winreg.SetValueEx(key, "NoModify", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, "NoRepair", 0, winreg.REG_DWORD, 1)
        
        winreg.CloseKey(key)
        return True
    except Exception as e:
        print(f"Registry error (may need admin): {e}")
        return False

def uninstall_application():
    """Uninstall the application"""
    try:
        # Remove from registry
        try:
            key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IT2WebITScanTool"
            winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        except:
            pass
        
        # Remove shortcuts
        shortcuts = [
            os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'), 
                        'Microsoft\\Windows\\Start Menu\\Programs\\IT2Innovations\\IT2WebITScanTool.lnk'),
            os.path.join(os.environ.get('USERPROFILE', ''), 'Desktop\\IT2WebITScanTool.lnk'),
        ]
        for s in shortcuts:
            try:
                os.remove(s)
            except:
                pass
        
        # Remove Start Menu folder
        try:
            start_folder = os.path.join(os.environ.get('ProgramData', 'C:\\ProgramData'),
                                       'Microsoft\\Windows\\Start Menu\\Programs\\IT2Innovations')
            if os.path.exists(start_folder):
                os.rmdir(start_folder)
        except:
            pass
        
        # Schedule removal of install directory
        install_dir = os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files'), 
                                   'IT2Innovations', 'IT2WebITScanTool')
        if os.path.exists(install_dir):
            # Create batch to delete after exit
            batch = os.path.join(tempfile.gettempdir(), 'uninstall_cleanup.bat')
            with open(batch, 'w') as f:
                f.write('@echo off\n')
                f.write('timeout /t 3 /nobreak >nul\n')
                f.write(f'rmdir /s /q "{install_dir}"\n')
                f.write(f'rmdir /s /q "{os.path.dirname(install_dir)}"\n')
                f.write(f'del "{batch}"\n')
            subprocess.Popen(batch, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
        
        return True
    except Exception as e:
        print(f"Uninstall error: {e}")
        return False


class SecurityScanner:
    """Security scanning engine"""
    def __init__(self, target_url: str, timeout: int = 10, progress_callback=None):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(target_url)
        self.base_domain = self.parsed_url.netloc
        self.timeout = timeout
        self.session = self._create_session()
        self.vulnerabilities = []
        self.progress_callback = progress_callback
        
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=2, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
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
        self.update_progress("Starting scan...")
        checks = [
            ("SSL/TLS", self.check_ssl_tls),
            ("Security Headers", self.check_security_headers),
            ("CORS", self.check_cors_configuration),
            ("Info Disclosure", self.check_information_disclosure),
            ("Clickjacking", self.check_clickjacking),
            ("XSS Protection", self.check_xss_protection),
            ("Cookies", self.check_cookie_security),
            ("Server Info", self.check_server_info),
            ("Directory Listing", self.check_directory_listing),
            ("Forms", self.check_form_security),
            ("Components", self.check_outdated_components),
            ("CSRF", self.check_csrf_protection),
            ("SQL Injection", self.check_sql_injection_indicators),
        ]
        for name, func in checks:
            try:
                self.update_progress(f"Checking: {name}...")
                func()
            except Exception as e:
                pass
        self.update_progress("Scan complete!")
    
    def check_ssl_tls(self):
        if not self.target_url.startswith('https://'):
            self.add_vulnerability("Missing HTTPS", "HIGH", "Not using HTTPS.", self.target_url, "Enable HTTPS.")
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
                        self.add_vulnerability("SSL Expiring", "MEDIUM", f"Certificate expires in {days_left} days.", self.target_url, "Renew certificate.")
                    if ssock.version() in ['TLSv1', 'TLSv1.1']:
                        self.add_vulnerability("Old TLS", "HIGH", f"Using {ssock.version()}.", self.target_url, "Use TLS 1.2+.")
        except: pass
    
    def check_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            for header, info in {
                'Strict-Transport-Security': ('MEDIUM', 'HSTS missing.', 'Add HSTS.'),
                'Content-Security-Policy': ('HIGH', 'CSP missing.', 'Implement CSP.'),
                'X-Frame-Options': ('MEDIUM', 'Clickjacking risk.', 'Add X-Frame-Options.'),
                'X-Content-Type-Options': ('LOW', 'MIME sniffing possible.', 'Add nosniff.')
            }.items():
                if header not in response.headers:
                    self.add_vulnerability(f"Missing {header}", info[0], info[1], self.target_url, info[2])
        except: pass
    
    def check_cors_configuration(self):
        try:
            resp = self.session.get(self.target_url, headers={'Origin': 'https://evil.com'}, timeout=self.timeout, verify=False)
            cors = resp.headers.get('Access-Control-Allow-Origin', '')
            if cors == '*':
                self.add_vulnerability("Wildcard CORS", "HIGH", "CORS allows any origin.", self.target_url, "Restrict origins.")
            elif cors == 'https://evil.com':
                self.add_vulnerability("CORS Reflection", "HIGH", "Reflects arbitrary origins.", self.target_url, "Validate origins.")
        except: pass
    
    def check_information_disclosure(self):
        for path in ['/.git/config', '/.env', '/wp-config.php', '/phpinfo.php', '/.htaccess']:
            try:
                if self.session.get(urljoin(self.target_url, path), timeout=self.timeout, verify=False).status_code == 200:
                    self.add_vulnerability("Exposed File", "HIGH", f"Accessible: {path}", urljoin(self.target_url, path), "Restrict access.")
            except: pass
    
    def check_clickjacking(self):
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            xfo = resp.headers.get('X-Frame-Options', '').upper()
            csp = resp.headers.get('Content-Security-Policy', '')
            if xfo not in ['DENY', 'SAMEORIGIN'] and 'frame-ancestors' not in csp:
                self.add_vulnerability("Clickjacking", "MEDIUM", "No frame protection.", self.target_url, "Add frame-ancestors or X-Frame-Options.")
        except: pass
    
    def check_xss_protection(self):
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            for form in BeautifulSoup(resp.text, 'html.parser').find_all('form'):
                if not any('csrf' in i.get('name','').lower() for i in form.find_all('input')):
                    self.add_vulnerability("No CSRF Token", "HIGH", "Form lacks CSRF protection.", form.get('action', self.target_url), "Add CSRF tokens.")
        except: pass
    
    def check_cookie_security(self):
        try:
            for cookie in self.session.get(self.target_url, timeout=self.timeout, verify=False).cookies:
                issues = [f for f, c in [("Secure", cookie.secure), ("HttpOnly", cookie.has_nonstandard_attr('HttpOnly')), ("SameSite", cookie.has_nonstandard_attr('SameSite'))] if not c]
                if issues:
                    self.add_vulnerability("Insecure Cookie", "MEDIUM", f"'{cookie.name}': {', '.join(issues)} missing.", self.target_url, "Set all cookie flags.")
        except: pass
    
    def check_server_info(self):
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            if resp.headers.get('Server'):
                self.add_vulnerability("Server Info Leak", "LOW", f"Server: {resp.headers['Server']}", self.target_url, "Suppress server header.")
        except: pass
    
    def check_directory_listing(self):
        for d in ['/images/', '/css/', '/js/', '/admin/']:
            try:
                resp = self.session.get(urljoin(self.target_url, d), timeout=self.timeout, verify=False)
                if resp.status_code == 200 and any(x in resp.text for x in ['Index of', 'Directory Listing']):
                    self.add_vulnerability("Dir Listing", "MEDIUM", f"Enabled: {d}", urljoin(self.target_url, d), "Disable directory listing.")
            except: pass
    
    def check_form_security(self):
        try:
            for form in BeautifulSoup(self.session.get(self.target_url, timeout=self.timeout, verify=False).text, 'html.parser').find_all('form'):
                if form.find_all('input', {'type': 'password'}) and form.get('method','GET').upper() == 'GET':
                    self.add_vulnerability("Password GET", "HIGH", "Password via GET method.", form.get('action'), "Use POST.")
        except: pass
    
    def check_outdated_components(self):
        try:
            for ver in re.findall(r'jquery[.-](\d+\.\d+\.\d+)', self.session.get(self.target_url, timeout=self.timeout, verify=False).text, re.I):
                parts = ver.split('.')
                if len(parts) >= 2 and (int(parts[0]) < 3 or (int(parts[0]) == 3 and int(parts[1]) < 5)):
                    self.add_vulnerability("Old jQuery", "MEDIUM", f"Version {ver}", self.target_url, "Update jQuery.")
        except: pass
    
    def check_csrf_protection(self):
        try:
            for form in BeautifulSoup(self.session.get(self.target_url, timeout=self.timeout, verify=False).text, 'html.parser').find_all('form'):
                if form.get('method','GET').upper() == 'POST' and not any(any(p in i.get('name','').lower() for p in ['csrf','token']) for i in form.find_all('input')):
                    self.add_vulnerability("Missing CSRF", "HIGH", "POST form lacks CSRF.", form.get('action'), "Add CSRF token.")
        except: pass
    
    def check_sql_injection_indicators(self):
        try:
            for form in BeautifulSoup(self.session.get(self.target_url, timeout=self.timeout, verify=False).text, 'html.parser').find_all('form'):
                action = form.get('action', self.target_url)
                data = {i.get('name',''): "' OR '1'='1" for i in form.find_all('input') if i.get('name')}
                if data:
                    resp = self.session.post(urljoin(self.target_url, action), data=data, timeout=self.timeout, verify=False) if form.get('method','GET').upper() == 'POST' else self.session.get(urljoin(self.target_url, action), params=data, timeout=self.timeout, verify=False)
                    if any(e in resp.text.lower() for e in ['sql','mysql','syntax error']):
                        self.add_vulnerability("Potential SQLi", "HIGH", "SQL error detected.", action, "Use parameterized queries.")
        except: pass
    
    def export_to_json(self, filename):
        data = {
            'scan_info': {'target_url': self.target_url, 'scan_date': datetime.datetime.now().isoformat(), 'total_vulnerabilities': len(self.vulnerabilities), 'tool_version': CURRENT_VERSION},
            'vulnerabilities': self.vulnerabilities,
            'severity_summary': {s: len([v for v in self.vulnerabilities if v['severity']==s]) for s in ['CRITICAL','HIGH','MEDIUM','LOW']}
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)


class AutoUpdater:
    def __init__(self):
        self.api_url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
    
    def check(self):
        if not check_internet_connection():
            return None
        try:
            resp = requests.get(self.api_url, headers={'Accept': 'application/vnd.github.v3+json'}, timeout=10)
            if resp.status_code == 200:
                release = resp.json()
                latest = release.get('tag_name','v0').replace('v','')
                if version.parse(latest) > version.parse(CURRENT_VERSION):
                    dl = next((a['browser_download_url'] for a in release.get('assets',[]) if a['name'].endswith('.exe')), None) or f"https://github.com/{GITHUB_REPO}/releases/latest/download/IT2WebITScanTool.exe"
                    return {'available': True, 'latest': latest, 'current': CURRENT_VERSION, 'url': dl, 'notes': release.get('body',''), 'release_url': release.get('html_url','')}
                return {'available': False, 'latest': latest, 'current': CURRENT_VERSION}
        except:
            return None
    
    def download(self, url, callback=None):
        try:
            path = os.path.join(tempfile.gettempdir(), 'IT2WebITScanTool_update.exe')
            resp = requests.get(url, stream=True, timeout=30)
            total = int(resp.headers.get('content-length', 0))
            if total == 0: return None
            dl = 0
            with open(path, 'wb') as f:
                for chunk in resp.iter_content(8192):
                    dl += len(chunk)
                    f.write(chunk)
                    if callback: callback(int((dl/total)*100))
            return path
        except:
            return None
    
    def install(self, new_exe):
        try:
            batch = os.path.join(tempfile.gettempdir(), 'update.bat')
            with open(batch, 'w') as f:
                f.write('@echo off\n')
                f.write('timeout /t 2 /nobreak >nul\n')
                f.write(f'copy /Y "{new_exe}" "{sys.executable}"\n')
                f.write(f'start "" "{sys.executable}"\n')
                f.write(f'del "{batch}"\n')
            subprocess.Popen(batch, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return True
        except:
            return False


class App:
    def __init__(self, root):
        self.root = root
        self.root.withdraw()
        self.root.title(f"IT2Innovations Web IT Scan Tool v{CURRENT_VERSION}")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 600)
        
        # Set AppUserModelID
        if sys.platform == 'win32':
            try:
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('IT2Innovations.IT2WebITScanTool')
            except: pass
        
        self.colors = {
            'bg': '#2b2b2b', 'fg': '#ffffff', 'select': '#404040',
            'btn': '#0d7377', 'btn_fg': '#ffffff',
            'critical': '#ff4444', 'high': '#ff8800', 'medium': '#ffbb33',
            'low': '#00C851', 'info': '#33b5e5', 'success': '#00C851', 'warning': '#ffbb33'
        }
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.root.configure(bg=self.colors['bg'])
        
        self.target_url = tk.StringVar()
        self.scanning = False
        self.scanner = None
        self.updater = AutoUpdater()
        
        self.setup_icon()
        self.setup_ui()
        
        self.root.deiconify()
        self.root.after(100, self.finalize_icon)
        self.root.after(2000, self.check_updates)
    
    def setup_icon(self):
        """Set the icon using the native Windows API"""
        self.icon_path = get_icon_path()
        
        if self.icon_path:
            # Try tkinter methods first
            try:
                self.root.iconbitmap(default=self.icon_path)
            except:
                pass
            
            try:
                img = Image.open(self.icon_path)
                photo = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, photo)
                self._photo = photo
            except:
                pass
    
    def finalize_icon(self):
        """Apply icon using Windows API after window is created"""
        if self.icon_path and sys.platform == 'win32':
            try:
                hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                set_window_icon(hwnd, self.icon_path)
            except:
                pass
    
    def setup_ui(self):
        # Menu
        menu = tk.Menu(self.root)
        self.root.config(menu=menu)
        
        file_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results (JSON)", command=self.export, accelerator="Ctrl+S")
        file_menu.add_command(label="Clear Results", command=self.clear_results)
        file_menu.add_separator()
        file_menu.add_command(label="Install Application", command=self.install_app)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        tools_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Check for Updates", command=self.manual_update)
        tools_menu.add_command(label="View GitHub", command=lambda: webbrowser.open(UPDATE_URL))
        
        help_menu = tk.Menu(menu, tearoff=0)
        menu.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Usage Guide", command=self.show_usage)
        
        # Main
        main = ttk.Frame(self.root, padding="10")
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(1, weight=1)
        main.rowconfigure(3, weight=1)
        
        # Title
        tf = ttk.Frame(main)
        tf.grid(row=0, column=0, columnspan=3, pady=(0,20))
        ttk.Label(tf, text="IT2Innovations Web IT Scan Tool", font=('Helvetica',16,'bold')).grid(row=0,column=0)
        ttk.Label(tf, text=f"v{CURRENT_VERSION}", font=('Helvetica',9), foreground=self.colors['info']).grid(row=1,column=0)
        
        # URL
        uf = ttk.Frame(main)
        uf.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0,10))
        uf.columnconfigure(1, weight=1)
        ttk.Label(uf, text="Target URL:").grid(row=0, column=0, padx=(0,10))
        self.url_entry = ttk.Entry(uf, textvariable=self.target_url, font=('Helvetica',11))
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0,10))
        self.url_entry.bind('<Return>', lambda e: self.start_scan())
        
        bf = ttk.Frame(uf)
        bf.grid(row=0, column=2)
        self.scan_btn = ttk.Button(bf, text="Start Scan", command=self.start_scan)
        self.scan_btn.grid(row=0, column=0, padx=(0,5))
        self.stop_btn = ttk.Button(bf, text="Stop", command=self.stop_scan, state='disabled')
        self.stop_btn.grid(row=0, column=1)
        
        # Progress
        pf = ttk.Frame(main)
        pf.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(0,10))
        pf.columnconfigure(0, weight=1)
        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(pf, textvariable=self.progress_var, font=('Helvetica',9)).grid(row=0, column=0, sticky="w")
        self.progress_bar = ttk.Progressbar(pf, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, sticky="ew", pady=(5,0))
        
        # Results
        paned = ttk.PanedWindow(main, orient=tk.HORIZONTAL)
        paned.grid(row=3, column=0, columnspan=3, sticky="nsew")
        main.rowconfigure(3, weight=1)
        
        # Left - Tree
        lf = ttk.Frame(paned)
        paned.add(lf, weight=1)
        
        ff = ttk.Frame(lf)
        ff.grid(row=0, column=0, sticky="ew", pady=(0,5))
        ttk.Label(ff, text="Filter:").grid(row=0, column=0, padx=(0,5))
        self.filter_var = tk.StringVar(value="All")
        self.filter_cb = ttk.Combobox(ff, textvariable=self.filter_var, values=["All","Critical","High","Medium","Low"], state='readonly', width=10)
        self.filter_cb.grid(row=0, column=1)
        self.filter_cb.bind('<<ComboboxSelected>>', self.filter)
        
        tf = ttk.Frame(lf)
        tf.grid(row=1, column=0, sticky="nsew")
        lf.columnconfigure(0, weight=1)
        lf.rowconfigure(1, weight=1)
        
        self.tree = ttk.Treeview(tf, columns=('Severity','Title'), show='headings')
        self.tree.heading('Severity', text='Severity')
        self.tree.heading('Title', text='Vulnerability')
        self.tree.column('Severity', width=80)
        self.tree.column('Title', width=400)
        
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tf.columnconfigure(0, weight=1)
        tf.rowconfigure(0, weight=1)
        
        self.tree.bind('<<TreeviewSelect>>', self.on_select)
        for s in ['critical','high','medium','low']:
            self.tree.tag_configure(s, foreground=self.colors[s])
        
        # Right - Details
        rf = ttk.Frame(paned)
        paned.add(rf, weight=2)
        
        ttk.Label(rf, text="Vulnerability Details", font=('Helvetica',11,'bold')).grid(row=0, column=0, sticky="w", pady=(0,5))
        
        self.detail = scrolledtext.ScrolledText(rf, wrap=tk.WORD, font=('Courier',10))
        self.detail.grid(row=1, column=0, sticky="nsew")
        rf.columnconfigure(0, weight=1)
        rf.rowconfigure(1, weight=1)
        
        for s in ['critical','high','medium','low']:
            self.detail.tag_configure(s, foreground=self.colors[s])
        self.detail.tag_configure('bold', font=('Courier',10,'bold'))
        self.detail.tag_configure('heading', font=('Courier',12,'bold'))
        
        # Status
        sf = ttk.Frame(main)
        sf.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(10,0))
        sf.columnconfigure(0, weight=1)
        
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(sf, textvariable=self.status_var, font=('Helvetica',9), foreground=self.colors['info']).grid(row=0, column=0, sticky="w")
        
        self.export_btn = ttk.Button(sf, text="Export JSON", command=self.export, state='disabled')
        self.export_btn.grid(row=0, column=1, sticky="e", padx=(0,5))
        self.clear_btn = ttk.Button(sf, text="Clear", command=self.clear_results)
        self.clear_btn.grid(row=0, column=2, sticky="e")
        
        self.root.bind('<Control-s>', lambda e: self.export())
    
    def check_updates(self):
        if not check_internet_connection():
            self.status_var.set("No internet - update check skipped")
            return
        
        result = self.updater.check()
        if result and result.get('available'):
            self.root.after(500, lambda: self.show_update_dialog(result))
        elif result:
            self.status_var.set(f"Up to date (v{CURRENT_VERSION})")
        else:
            self.status_var.set("Update check failed - check connection")
    
    def manual_update(self):
        if not check_internet_connection():
            messagebox.showinfo("No Internet", "Internet connection not available.\nPlease check your connection and try again.")
            return
        
        self.status_var.set("Checking for updates...")
        result = self.updater.check()
        
        if result:
            self.show_update_dialog(result, up_to_date=not result.get('available'))
        else:
            messagebox.showinfo("Update Check", "Could not check for updates.\nPlease verify your internet connection.")
            self.status_var.set("Ready")
    
    def show_update_dialog(self, info, up_to_date=False):
        d = tk.Toplevel(self.root)
        if self.icon_path:
            try: d.iconbitmap(self.icon_path)
            except: pass
        
        if up_to_date:
            d.title("Up to Date")
            h = 400
        else:
            d.title("Update Available!")
            h = 600
        
        d.geometry(f"500x{h}")
        d.configure(bg=self.colors['bg'])
        d.resizable(False, False)
        d.transient(self.root)
        d.grab_set()
        
        d.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width()-500)//2
        y = self.root.winfo_y() + (self.root.winfo_height()-h)//2
        d.geometry(f"+{x}+{y}")
        
        if up_to_date:
            tk.Label(d, text="You're Up to Date!", font=('Helvetica',16,'bold'), bg=self.colors['bg'], fg=self.colors['success']).pack(pady=(30,10))
            tk.Label(d, text="\u2713", font=('Helvetica',48), bg=self.colors['bg'], fg=self.colors['success']).pack(pady=10)
            f = tk.Frame(d, bg=self.colors['bg']); f.pack(fill=tk.BOTH, padx=30, pady=10)
            tk.Label(f, text=f"Current: v{info.get('current',CURRENT_VERSION)}", font=('Helvetica',11), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=5)
            tk.Label(f, text=f"Latest: v{info.get('latest',CURRENT_VERSION)}", font=('Helvetica',11), bg=self.colors['bg'], fg=self.colors['success']).pack(pady=5)
            tk.Label(f, text="No update needed.", font=('Helvetica',10), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=20)
            tk.Button(d, text="Close", font=('Helvetica',11), bg=self.colors['select'], fg=self.colors['fg'], relief=tk.FLAT, padx=30, pady=10, command=d.destroy).pack(pady=20)
        else:
            tk.Label(d, text="Update Available!", font=('Helvetica',16,'bold'), bg=self.colors['bg'], fg=self.colors['warning']).pack(pady=(30,10))
            tk.Label(d, text="\u2B06", font=('Helvetica',48), bg=self.colors['bg'], fg=self.colors['warning']).pack(pady=10)
            
            f = tk.Frame(d, bg=self.colors['bg']); f.pack(fill=tk.BOTH, padx=30, pady=10)
            tk.Label(f, text="Current:", font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w')
            tk.Label(f, text=f"v{info['current']}", font=('Helvetica',12), bg=self.colors['bg'], fg=self.colors['info']).pack(anchor='w', pady=(0,10))
            tk.Label(f, text="Latest:", font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w')
            tk.Label(f, text=f"v{info['latest']}", font=('Helvetica',12), bg=self.colors['bg'], fg=self.colors['warning']).pack(anchor='w', pady=(0,15))
            tk.Frame(f, height=1, bg=self.colors['info']).pack(fill=tk.X, pady=10)
            
            if info.get('notes'):
                tk.Label(f, text="What's New:", font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(anchor='w', pady=(0,5))
                n = tk.Text(f, height=8, width=55, font=('Helvetica',9), bg=self.colors['select'], fg=self.colors['fg'], relief=tk.FLAT, wrap=tk.WORD)
                n.pack(fill=tk.BOTH, pady=(0,10))
                n.insert('1.0', info['notes'][:500])
                n.config(state='disabled')
            
            auto = tk.BooleanVar(value=True)
            tk.Checkbutton(f, text="Auto-install after download", variable=auto, bg=self.colors['bg'], fg=self.colors['fg'], selectcolor=self.colors['select']).pack(anchor='w', pady=5)
            
            prog = ttk.Progressbar(f, mode='determinate', length=400)
            plabel = tk.Label(f, text="", font=('Helvetica',9), bg=self.colors['bg'], fg=self.colors['info'])
            
            btns = tk.Frame(d, bg=self.colors['bg']); btns.pack(pady=20)
            
            def do_update():
                dl_btn.config(state='disabled'); cl_btn.config(state='disabled')
                prog.pack(fill=tk.X, pady=5); plabel.pack()
                plabel.config(text="Downloading...")
                
                def dl():
                    exe = self.updater.download(info['url'], lambda p: (prog.config(value=p), plabel.config(text=f"Downloading: {p}%"), d.update_idletasks()))
                    if exe:
                        plabel.config(text="Download complete!")
                        if auto.get():
                            plabel.config(text="Installing..."); d.update_idletasks()
                            if self.updater.install(exe):
                                plabel.config(text="Restarting..."); d.after(1500, self.root.quit)
                            else:
                                plabel.config(text="Opening page..."); webbrowser.open(info['release_url'])
                        else:
                            messagebox.showinfo("Done", f"Downloaded to:\n{exe}", parent=d)
                    else:
                        plabel.config(text="Failed. Opening page..."); webbrowser.open(info['release_url'])
                    dl_btn.config(state='normal'); cl_btn.config(state='normal')
                
                threading.Thread(target=dl, daemon=True).start()
            
            dl_btn = tk.Button(btns, text="Update Now", font=('Helvetica',11,'bold'), bg=self.colors['btn'], fg=self.colors['btn_fg'], relief=tk.FLAT, padx=20, pady=10, command=do_update)
            dl_btn.pack(side=tk.LEFT, padx=(0,10))
            cl_btn = tk.Button(btns, text="Remind Later", font=('Helvetica',11), bg=self.colors['select'], fg=self.colors['fg'], relief=tk.FLAT, padx=20, pady=10, command=d.destroy)
            cl_btn.pack(side=tk.LEFT)
    
    def show_about(self):
        d = tk.Toplevel(self.root)
        d.title("About")
        d.geometry("500x550")
        d.configure(bg=self.colors['bg'])
        d.resizable(False, False)
        d.transient(self.root)
        d.grab_set()
        
        if self.icon_path:
            try: d.iconbitmap(self.icon_path)
            except: pass
        
        d.update_idletasks()
        d.geometry(f"+{self.root.winfo_x()+(self.root.winfo_width()-500)//2}+{self.root.winfo_y()+(self.root.winfo_height()-550)//2}")
        
        tk.Label(d, text="IT2Innovations Web IT Scan Tool", font=('Helvetica',14,'bold'), bg=self.colors['bg'], fg=self.colors['info']).pack(pady=(30,5))
        tk.Label(d, text=f"Version {CURRENT_VERSION}", font=('Helvetica',11), bg=self.colors['bg'], fg=self.colors['fg']).pack(pady=(0,20))
        
        f = tk.Frame(d, bg=self.colors['bg']); f.pack(fill=tk.BOTH, padx=40)
        for l,v in [("Creator:","Mike Larios"),("Validation:","Mike Larios"),("License:","MIT & Apache"),("Repo:",f"github.com/{GITHUB_REPO}")]:
            r = tk.Frame(f, bg=self.colors['bg']); r.pack(fill=tk.X, pady=2)
            tk.Label(r, text=l, font=('Helvetica',10,'bold'), bg=self.colors['bg'], fg=self.colors['fg']).pack(side=tk.LEFT)
            tk.Label(r, text=v, font=('Helvetica',10), bg=self.colors['bg'], fg=self.colors['info']).pack(side=tk.LEFT, padx=(5,0))
        
        tk.Frame(f, height=2, bg=self.colors['info']).pack(fill=tk.X, pady=15)
        tk.Label(f, text="IMPORTANT LEGAL NOTICE", font=('Helvetica',11,'bold'), bg=self.colors['bg'], fg=self.colors['high']).pack(pady=(5,10))
        tk.Label(f, text="This program is a testing tool, Pen Testing tool, and a tool used to exploit vulnerabilities of weakened or compromised websites.\n\nThis can get you in trouble if you are not authorized by the site/ISP/Owner of the domain you are testing against.\n\nAll legal ramifications will be on you, not any companies, persons, or devices mentioned in this file. We hold no legal or other responsible parts to the usage of this application.\n\nThis is created and considered 'AS-IS' best effort coded.", font=('Helvetica',9), bg=self.colors['bg'], fg=self.colors['fg'], wraplength=420, justify=tk.LEFT).pack(pady=(0,15))
        tk.Button(d, text="Close", font=('Helvetica',11), bg=self.colors['select'], fg=self.colors['fg'], relief=tk.FLAT, padx=30, pady=10, command=d.destroy).pack(pady=(0,20))
    
    def show_usage(self):
        messagebox.showinfo("Usage Guide", 
            "USAGE GUIDE\n\n"
            "1. Enter target URL\n"
            "2. Click Start Scan\n"
            "3. Confirm authorization\n"
            "4. Review results\n"
            "5. Export to JSON\n\n"
            "INSTALLATION:\n"
            "Use File > Install Application to install\n"
            "to Program Files with Start Menu shortcuts.\n\n"
            "AUTO-UPDATE:\n"
            "Checks for updates on startup.\n"
            "Can auto-download and install updates."
        )
    
    def install_app(self):
        if not messagebox.askyesno("Install", 
            "Install IT2WebITScanTool to Program Files?\n\n"
            "This will:\n"
            "- Copy to Program Files\n"
            "- Create Start Menu shortcut\n"
            "- Create Desktop shortcut\n"
            "- Add to installed programs list\n\n"
            "Continue?"):
            return
        
        if install_application():
            messagebox.showinfo("Installation Complete", 
                "Application installed successfully!\n\n"
                "A new instance is launching from the installed location.\n"
                "You can close this instance.\n\n"
                "Find it in:\n"
                "- Start Menu > IT2Innovations\n"
                "- Desktop shortcut\n"
                "- Program Files")
            self.root.quit()
        else:
            messagebox.showerror("Installation Failed", 
                "Could not install application.\n"
                "Try running as Administrator for full installation.")
    
    def start_scan(self):
        url = self.target_url.get().strip()
        if not url: return messagebox.showwarning("No URL", "Enter a target URL.")
        if not url.startswith(('http://','https://')): url = 'https://'+url; self.target_url.set(url)
        if not messagebox.askyesno("Authorization", "Do you have authorization to scan this target?", icon='warning'): return
        
        self.clear_results()
        self.scan_btn.config(state='disabled'); self.stop_btn.config(state='normal')
        self.export_btn.config(state='disabled'); self.url_entry.config(state='disabled')
        self.filter_cb.config(state='disabled')
        self.progress_bar.start(10); self.progress_var.set("Scanning..."); self.status_var.set("Scanning...")
        self.scanning = True
        threading.Thread(target=self._scan, args=(url,), daemon=True).start()
    
    def _scan(self, url):
        try:
            self.scanner = SecurityScanner(url, progress_callback=lambda m: self.root.after(0, self.progress_var.set, m))
            self.scanner.scan()
            self.root.after(0, self._scan_done)
        except Exception as e:
            self.root.after(0, self._scan_err, str(e))
    
    def _scan_done(self):
        self.progress_bar.stop()
        c = len(self.scanner.vulnerabilities)
        self.progress_var.set(f"Done! Found {c} vulnerabilities."); self.status_var.set(f"Found {c} vulnerabilities")
        self.scan_btn.config(state='normal'); self.stop_btn.config(state='disabled'); self.export_btn.config(state='normal')
        self.url_entry.config(state='normal'); self.filter_cb.config(state='readonly')
        self.populate(); self.scanning = False
    
    def _scan_err(self, msg):
        self.progress_bar.stop(); self.progress_var.set(f"Error: {msg}"); self.status_var.set("Failed")
        self.scan_btn.config(state='normal'); self.stop_btn.config(state='disabled')
        self.url_entry.config(state='normal'); self.filter_cb.config(state='readonly')
        self.scanning = False
        messagebox.showerror("Error", f"Scan failed:\n\n{msg}")
    
    def stop_scan(self):
        self.scanning = False; self.progress_bar.stop()
        self.progress_var.set("Stopped"); self.status_var.set("Stopped")
        self.scan_btn.config(state='normal'); self.stop_btn.config(state='disabled')
        self.url_entry.config(state='normal'); self.filter_cb.config(state='readonly')
    
    def populate(self, filter_sev="All"):
        for i in self.tree.get_children(): self.tree.delete(i)
        if not self.scanner: return
        order = {'CRITICAL':0,'HIGH':1,'MEDIUM':2,'LOW':3}
        for v in sorted(self.scanner.vulnerabilities, key=lambda x: order.get(x['severity'].upper(),4)):
            if filter_sev=="All" or v['severity'].upper()==filter_sev.upper():
                self.tree.insert('','end',values=(v['severity'],v['title']),tags=(v['severity'].lower(),))
    
    def filter(self, e=None): self.populate(self.filter_var.get())
    
    def on_select(self, e):
        sel = self.tree.selection()
        if not sel: return
        title = self.tree.item(sel[0])['values'][1]
        if self.scanner:
            for v in self.scanner.vulnerabilities:
                if v['title']==title: self.show_detail(v); break
    
    def show_detail(self, v):
        self.detail.delete('1.0', tk.END)
        t = v['severity'].lower()
        self.detail.insert('1.0', "VULNERABILITY DETAILS\n", 'heading')
        self.detail.insert(tk.END, "-"*50+"\n\n")
        self.detail.insert(tk.END, "Title: ",'bold'); self.detail.insert(tk.END, f"{v['title']}\n\n")
        self.detail.insert(tk.END, "Severity: ",'bold'); self.detail.insert(tk.END, f"{v['severity']}\n",t)
        self.detail.insert(tk.END, "\nLocation:\n",'bold'); self.detail.insert(tk.END, f"  {v['location']}\n\n")
        self.detail.insert(tk.END, "Description:\n",'bold'); self.detail.insert(tk.END, f"  {v['description']}\n\n")
        if v['evidence']: self.detail.insert(tk.END, "Evidence:\n",'bold'); self.detail.insert(tk.END, f"  {v['evidence']}\n\n")
        self.detail.insert(tk.END, "Fix:\n",'bold'); self.detail.insert(tk.END, f"  {v['fix']}\n\n")
        self.detail.insert(tk.END, "Detected:\n",'bold'); self.detail.insert(tk.END, f"  {v['timestamp']}\n")
        self.detail.see('1.0')
    
    def export(self):
        if not self.scanner or not self.scanner.vulnerabilities: return messagebox.showwarning("Nothing", "No results.")
        fn = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON","*.json")], initialfile=f"scan_{self.scanner.base_domain}_{datetime.datetime.now():%Y%m%d_%H%M%S}.json")
        if fn:
            try:
                self.scanner.export_to_json(fn)
                if messagebox.askyesno("Done", f"Saved to:\n{fn}\n\nOpen?"): os.startfile(fn)
            except Exception as e: messagebox.showerror("Error", str(e))
    
    def clear_results(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        self.detail.delete('1.0', tk.END)
        self.progress_var.set("Ready"); self.status_var.set("Ready")
        self.export_btn.config(state='disabled'); self.scanner = None

def main():
    # Check for uninstall flag
    if '--uninstall' in sys.argv:
        if messagebox.askyesno("Uninstall", "Uninstall IT2WebITScanTool?\n\nThis will remove the application and all shortcuts."):
            if uninstall_application():
                messagebox.showinfo("Uninstalled", "Application has been uninstalled.")
            else:
                messagebox.showerror("Error", "Uninstall failed.\nRun as Administrator and try again.")
        sys.exit(0)
    
    root = tk.Tk()
    
    if sys.platform == 'win32':
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID('IT2Innovations.IT2WebITScanTool')
        except: pass
    
    app = App(root)
    
    root.update_idletasks()
    w, h = 1200, 800
    root.geometry(f'{w}x{h}+{(root.winfo_screenwidth()-w)//2}+{(root.winfo_screenheight()-h)//2}')
    
    root.mainloop()

if __name__ == "__main__":
    main()