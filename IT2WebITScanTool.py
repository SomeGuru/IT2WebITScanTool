#!/usr/bin/env python3
"""
IT2Innovations Web IT Scan Tool
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
import shutil

# Suppress SSL warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Version info - VERSION 1.0.2
CURRENT_VERSION = "1.0.2"
GITHUB_REPO = "someguru/IT2WebITScanTool"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}"
UPDATE_URL = f"https://github.com/{GITHUB_REPO}/releases/latest"
RELEASES_API = f"{GITHUB_API}/releases/latest"
VERSION_URL = f"https://raw.githubusercontent.com/{GITHUB_REPO}/main/version.txt"

class SecurityScanner:
    """Backend scanner class"""
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
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            'User-Agent': f'IT2WebITScanTool/{CURRENT_VERSION}'
        })
        return session
    
    def add_vulnerability(self, title: str, severity: str, description: str, 
                          location: str, fix: str, evidence: str = ""):
        self.vulnerabilities.append({
            'title': title,
            'severity': severity,
            'description': description,
            'location': location,
            'fix': fix,
            'evidence': evidence,
            'timestamp': datetime.datetime.now().isoformat()
        })
    
    def update_progress(self, message: str):
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
    
    def check_ssl_tls(self):
        if not self.target_url.startswith('https://'):
            self.add_vulnerability(
                "Missing HTTPS", "HIGH",
                "Website is not using HTTPS. Data is transmitted in plain text.",
                self.target_url,
                "Implement SSL/TLS certificate and force HTTPS redirect.",
                "HTTP used instead of HTTPS"
            )
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
                        self.add_vulnerability(
                            "SSL Certificate Expiring Soon", "MEDIUM",
                            f"SSL certificate expires in {days_left} days.",
                            self.target_url, "Renew SSL certificate before expiration.",
                            f"Expiry date: {cert['notAfter']}"
                        )
                    
                    tls_version = ssock.version()
                    if tls_version in ['TLSv1', 'TLSv1.1']:
                        self.add_vulnerability(
                            "Outdated TLS Version", "HIGH",
                            f"Server supports outdated {tls_version}.",
                            self.target_url,
                            "Disable TLS 1.0/1.1. Enable only TLS 1.2 and 1.3.",
                            f"Supported version: {tls_version}"
                        )
        except:
            pass
    
    def check_security_headers(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': {
                    'severity': 'MEDIUM',
                    'desc': 'HSTS header not set. MitM attacks possible.',
                    'fix': 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains'
                },
                'Content-Security-Policy': {
                    'severity': 'HIGH',
                    'desc': 'CSP header not set. Vulnerable to XSS attacks.',
                    'fix': 'Implement Content-Security-Policy header.'
                },
                'X-Frame-Options': {
                    'severity': 'MEDIUM',
                    'desc': 'X-Frame-Options not set. Vulnerable to clickjacking.',
                    'fix': 'Add X-Frame-Options: DENY or SAMEORIGIN.'
                },
                'X-Content-Type-Options': {
                    'severity': 'LOW',
                    'desc': 'X-Content-Type-Options not set. MIME sniffing possible.',
                    'fix': 'Add X-Content-Type-Options: nosniff.'
                },
                'Referrer-Policy': {
                    'severity': 'LOW',
                    'desc': 'Referrer-Policy header not set.',
                    'fix': 'Add Referrer-Policy: strict-origin-when-cross-origin.'
                }
            }
            
            for header, info in security_headers.items():
                if header not in headers:
                    self.add_vulnerability(
                        f"Missing: {header}", info['severity'],
                        info['desc'], self.target_url, info['fix']
                    )
        except:
            pass
    
    def check_cors_configuration(self):
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(
                self.target_url, headers=headers, 
                timeout=self.timeout, verify=False
            )
            cors_headers = response.headers.get('Access-Control-Allow-Origin', '')
            
            if cors_headers == '*':
                self.add_vulnerability(
                    "Dangerous CORS - Wildcard", "HIGH",
                    "CORS allows any origin (*).", self.target_url,
                    "Restrict to specific trusted domains.",
                    f"Allow-Origin: {cors_headers}"
                )
            elif cors_headers == 'https://evil.com':
                self.add_vulnerability(
                    "CORS Origin Reflection", "HIGH",
                    "CORS reflects arbitrary origins.", self.target_url,
                    "Implement strict origin validation.",
                    f"Reflected origin: {cors_headers}"
                )
        except:
            pass
    
    def check_information_disclosure(self):
        try:
            sensitive_paths = [
                '/.git/config', '/.env', '/backup', '/wp-config.php',
                '/config.php', '/phpinfo.php', '/server-status',
                '/.htaccess', '/robots.txt', '/sitemap.xml'
            ]
            
            for path in sensitive_paths:
                url = urljoin(self.target_url, path)
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    self.add_vulnerability(
                        "Sensitive File Exposed", "HIGH",
                        f"File accessible: {path}", url,
                        "Restrict access via web server configuration.",
                        f"URL: {url}"
                    )
            
            response = self.session.get(
                urljoin(self.target_url, "/nonexistent_path_12345"),
                timeout=self.timeout, verify=False
            )
            
            error_indicators = [
                'stack trace', 'syntax error', 'mysql_fetch',
                'on line', 'warning:', 'fatal error'
            ]
            
            for indicator in error_indicators:
                if indicator in response.text.lower():
                    self.add_vulnerability(
                        "Verbose Error Messages", "MEDIUM",
                        "Detailed errors may reveal system info.",
                        self.target_url,
                        "Configure custom error pages. Disable debug mode.",
                        f"Indicator: {indicator}"
                    )
                    break
        except:
            pass
    
    def check_clickjacking(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            x_frame = response.headers.get('X-Frame-Options', '').upper()
            csp = response.headers.get('Content-Security-Policy', '')
            
            if x_frame not in ['DENY', 'SAMEORIGIN'] and 'frame-ancestors' not in csp:
                self.add_vulnerability(
                    "Clickjacking Vulnerability", "MEDIUM",
                    "No clickjacking protection detected.", self.target_url,
                    "Add X-Frame-Options: DENY or frame-ancestors in CSP."
                )
        except:
            pass
    
    def check_xss_protection(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            for form in forms:
                inputs = form.find_all('input')
                if not any('csrf' in inp.get('name', '').lower() for inp in inputs):
                    self.add_vulnerability(
                        "Form Without CSRF Token", "HIGH",
                        "Form found without CSRF protection.",
                        form.get('action', self.target_url),
                        "Implement CSRF tokens in all forms."
                    )
        except:
            pass
    
    def check_cookie_security(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            for cookie in response.cookies:
                issues = []
                if not cookie.secure:
                    issues.append("Secure flag missing")
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append("HttpOnly flag missing")
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append("SameSite attribute missing")
                
                if issues:
                    self.add_vulnerability(
                        "Insecure Cookie", "MEDIUM",
                        f"Cookie '{cookie.name}': {', '.join(issues)}",
                        self.target_url,
                        "Set Secure, HttpOnly, and SameSite flags.",
                        f"Issues: {', '.join(issues)}"
                    )
        except:
            pass
    
    def check_server_info(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            server = response.headers.get('Server', '')
            powered_by = response.headers.get('X-Powered-By', '')
            
            if server:
                self.add_vulnerability(
                    "Server Info Disclosure", "LOW",
                    f"Server header reveals: {server}", self.target_url,
                    "Suppress or modify Server header.",
                    f"Server: {server}"
                )
            if powered_by:
                self.add_vulnerability(
                    "Technology Disclosure", "LOW",
                    f"X-Powered-By reveals: {powered_by}", self.target_url,
                    "Remove X-Powered-By header.",
                    f"X-Powered-By: {powered_by}"
                )
        except:
            pass
    
    def check_directory_listing(self):
        try:
            common_dirs = ['/images/', '/css/', '/js/', '/assets/', '/uploads/', '/admin/']
            for directory in common_dirs:
                url = urljoin(self.target_url, directory)
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    if any(x in response.text for x in ['Index of /', 'Directory Listing', 'Parent Directory']):
                        self.add_vulnerability(
                            "Directory Listing Enabled", "MEDIUM",
                            f"Directory listing enabled: {directory}", url,
                            "Disable directory listing in web server config.",
                            f"URL: {url}"
                        )
        except:
            pass
    
    def check_form_security(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', self.target_url)
                method = form.get('method', 'GET').upper()
                
                if form.find_all('input', {'type': 'password'}) and method == 'GET':
                    self.add_vulnerability(
                        "Password Form Uses GET", "HIGH",
                        "Password form uses GET method.", action,
                        "Change to POST method with CSRF protection.",
                        f"Form action: {action}"
                    )
        except:
            pass
    
    def check_outdated_components(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            content = response.text
            
            jquery_patterns = [r'jquery[.-](\d+\.\d+\.\d+)', r'jquery/(\d+\.\d+\.\d+)']
            for pattern in jquery_patterns:
                for ver in re.findall(pattern, content, re.IGNORECASE):
                    parts = ver.split('.')
                    if len(parts) >= 2:
                        major, minor = int(parts[0]), int(parts[1])
                        if major < 3 or (major == 3 and minor < 5):
                            self.add_vulnerability(
                                "Outdated jQuery", "MEDIUM",
                                f"jQuery version {ver} detected.", self.target_url,
                                "Update to jQuery 3.5.0+.", f"Version: {ver}"
                            )
        except:
            pass
    
    def check_csrf_protection(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                if form.get('method', 'GET').upper() == 'POST':
                    inputs = form.find_all('input')
                    csrf_patterns = ['csrf', 'token', 'nonce', '_token', 'authenticity_token']
                    has_csrf = any(
                        any(p in inp.get('name', '').lower() or p in inp.get('id', '').lower() 
                            for p in csrf_patterns)
                        for inp in inputs
                    )
                    
                    if not has_csrf:
                        self.add_vulnerability(
                            "Missing CSRF Protection", "HIGH",
                            "POST form without CSRF token.",
                            form.get('action', self.target_url),
                            "Implement CSRF tokens using framework protection."
                        )
        except:
            pass
    
    def check_sql_injection_indicators(self):
        try:
            response = self.session.get(self.target_url, timeout=self.timeout, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', self.target_url)
                method = form.get('method', 'GET').upper()
                
                test_data = {}
                for inp in form.find_all('input'):
                    name = inp.get('name', '')
                    if name:
                        test_data[name] = "' OR '1'='1"
                
                if test_data:
                    if method == 'POST':
                        resp = self.session.post(
                            urljoin(self.target_url, action),
                            data=test_data, timeout=self.timeout, verify=False
                        )
                    else:
                        resp = self.session.get(
                            urljoin(self.target_url, action),
                            params=test_data, timeout=self.timeout, verify=False
                        )
                    
                    sql_errors = ['sql', 'mysql', 'syntax error', 'odbc', 'driver']
                    if any(e in resp.text.lower() for e in sql_errors):
                        self.add_vulnerability(
                            "Potential SQL Injection", "HIGH",
                            "SQL error detected in form response.", action,
                            "Use parameterized queries. Sanitize inputs.",
                            "SQL error in response"
                        )
        except:
            pass
    
    def export_to_json(self, filename: str):
        """Export vulnerabilities to JSON file"""
        export_data = {
            'scan_info': {
                'target_url': self.target_url,
                'base_domain': self.base_domain,
                'scan_date': datetime.datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'tool_version': CURRENT_VERSION
            },
            'vulnerabilities': self.vulnerabilities,
            'severity_summary': {
                'critical': len([v for v in self.vulnerabilities if v['severity'] == 'CRITICAL']),
                'high': len([v for v in self.vulnerabilities if v['severity'] == 'HIGH']),
                'medium': len([v for v in self.vulnerabilities if v['severity'] == 'MEDIUM']),
                'low': len([v for v in self.vulnerabilities if v['severity'] == 'LOW'])
            },
            'recommendations': [
                "Implement HTTPS with valid SSL/TLS certificates",
                "Set all recommended security headers",
                "Use parameterized queries for all database operations",
                "Implement proper input validation and output encoding",
                "Keep all software and libraries updated",
                "Regular security testing and code reviews",
                "Implement proper authentication and authorization",
                "Enable comprehensive logging and monitoring"
            ]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)


class AutoUpdater:
    """Handles automatic updates"""
    
    def __init__(self, current_version, github_repo):
        self.current_version = current_version
        self.github_repo = github_repo
        self.api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"
        self.download_url_template = f"https://github.com/{github_repo}/releases/latest/download/IT2WebITScanTool.exe"
    
    def check_for_update(self):
        """Check if a new version is available"""
        try:
            response = requests.get(self.api_url, headers={'Accept': 'application/vnd.github.v3+json'}, timeout=5)
            
            if response.status_code == 200:
                release_data = response.json()
                latest_tag = release_data.get('tag_name', 'v0.0.0').replace('v', '')
                
                if version.parse(latest_tag) > version.parse(self.current_version):
                    # Get download URL
                    download_url = None
                    for asset in release_data.get('assets', []):
                        if asset['name'].endswith('.exe'):
                            download_url = asset['browser_download_url']
                            break
                    
                    if not download_url:
                        download_url = self.download_url_template
                    
                    return {
                        'update_available': True,
                        'latest_version': latest_tag,
                        'current_version': self.current_version,
                        'download_url': download_url,
                        'release_notes': release_data.get('body', 'No release notes available.'),
                        'release_url': release_data.get('html_url', '')
                    }
                else:
                    return {
                        'update_available': False,
                        'latest_version': latest_tag,
                        'current_version': self.current_version
                    }
            
            return None
            
        except Exception as e:
            print(f"Update check failed: {e}")
            return None
    
    def download_update(self, download_url, progress_callback=None):
        """Download the update file"""
        try:
            # Create temp directory for download
            temp_dir = tempfile.gettempdir()
            new_exe_path = os.path.join(temp_dir, f"IT2WebITScanTool_{self.current_version}_update.exe")
            
            # Download with progress
            response = requests.get(download_url, stream=True)
            total_size = int(response.headers.get('content-length', 0))
            
            if total_size == 0:
                return None
            
            block_size = 8192
            downloaded = 0
            
            with open(new_exe_path, 'wb') as f:
                for data in response.iter_content(block_size):
                    downloaded += len(data)
                    f.write(data)
                    if progress_callback:
                        progress = int((downloaded / total_size) * 100)
                        progress_callback(progress)
            
            return new_exe_path
            
        except Exception as e:
            print(f"Download failed: {e}")
            return None
    
    def install_update(self, new_exe_path):
        """Install the update by replacing current executable"""
        try:
            current_exe = sys.executable
            
            # Create batch script to replace the executable
            batch_script = os.path.join(tempfile.gettempdir(), "update_installer.bat")
            
            with open(batch_script, 'w') as f:
                f.write("@echo off\n")
                f.write("timeout /t 2 /nobreak >nul\n")
                f.write(f'copy /Y "{new_exe_path}" "{current_exe}"\n')
                f.write(f'start "" "{current_exe}"\n')
                f.write(f'del "{batch_script}"\n')
            
            # Run the batch script
            subprocess.Popen(
                batch_script,
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            return True
            
        except Exception as e:
            print(f"Install failed: {e}")
            return False


class SecurityScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(f"IT2Innovations Web IT Scan Tool v{CURRENT_VERSION}")
        self.root.geometry("1200x800")
        
        # Set minimum window size
        self.root.minsize(1000, 600)
        
        # Set taskbar icon properly for Windows
        self.setup_app_icon()
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Colors
        self.colors = {
            'bg': '#2b2b2b',
            'fg': '#ffffff',
            'select_bg': '#404040',
            'button_bg': '#0d7377',
            'button_fg': '#ffffff',
            'entry_bg': '#404040',
            'entry_fg': '#ffffff',
            'critical': '#ff4444',
            'high': '#ff8800',
            'medium': '#ffbb33',
            'low': '#00C851',
            'info': '#33b5e5',
            'success': '#00C851',
            'warning': '#ffbb33',
            'error': '#ff4444'
        }
        
        self.root.configure(bg=self.colors['bg'])
        
        # Variables
        self.target_url = tk.StringVar()
        self.scanning = False
        self.scanner = None
        self.icon_image = None
        self.updater = AutoUpdater(CURRENT_VERSION, GITHUB_REPO)
        
        self.setup_ui()
        
        # Check for updates on startup (silently, show dialog only if update available)
        self.root.after(1500, self.check_for_updates_silent)
    
    def setup_app_icon(self):
        """Setup application icon for window and taskbar"""
        try:
            # Download icon if not exists
            icon_path = os.path.join(tempfile.gettempdir(), "it2_icon.ico")
            
            if not os.path.exists(icon_path):
                icon_url = "http://www.it2innovations.com/images/favicon.ico"
                urllib.request.urlretrieve(icon_url, icon_path)
            
            # Set icon for window
            self.root.iconbitmap(default=icon_path)
            
            # Set AppUserModelID for Windows taskbar
            if sys.platform == 'win32':
                try:
                    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                        'IT2Innovations.WebITScanTool.1.0'
                    )
                except:
                    pass
            
            # Also try with PIL for better compatibility
            try:
                img = Image.open(icon_path)
                self.icon_image = ImageTk.PhotoImage(img)
                self.root.iconphoto(True, self.icon_image)
            except:
                pass
                
        except Exception as e:
            print(f"Could not set icon: {e}")
    
    def setup_ui(self):
        """Setup the user interface"""
        # Menu bar
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Export Results (JSON)", command=self.export_results, accelerator="Ctrl+S")
        file_menu.add_command(label="Clear Results", command=self.clear_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Alt+F4")
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Check for Updates", command=self.manual_update_check)
        tools_menu.add_command(label="View GitHub Repository", command=lambda: webbrowser.open(UPDATE_URL))
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about_dialog)
        help_menu.add_command(label="Usage Guide", command=self.show_usage)
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(3, weight=1)
        
        # Title
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        title_label = ttk.Label(
            title_frame, 
            text="IT2Innovations Web IT Scan Tool",
            font=('Helvetica', 16, 'bold')
        )
        title_label.grid(row=0, column=0)
        
        version_label = ttk.Label(
            title_frame,
            text=f"v{CURRENT_VERSION}",
            font=('Helvetica', 9),
            foreground=self.colors['info']
        )
        version_label.grid(row=1, column=0)
        
        # URL Input Frame
        url_frame = ttk.Frame(main_frame)
        url_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        url_frame.columnconfigure(1, weight=1)
        
        ttk.Label(url_frame, text="Target URL:").grid(row=0, column=0, padx=(0, 10))
        
        self.url_entry = ttk.Entry(
            url_frame, 
            textvariable=self.target_url,
            font=('Helvetica', 11),
            width=50
        )
        self.url_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 10))
        
        # Bind Enter key to start scan
        self.url_entry.bind('<Return>', lambda e: self.start_scan())
        
        # Buttons
        button_frame = ttk.Frame(url_frame)
        button_frame.grid(row=0, column=2)
        
        self.scan_button = ttk.Button(
            button_frame,
            text="Start Scan",
            command=self.start_scan
        )
        self.scan_button.grid(row=0, column=0, padx=(0, 5))
        
        self.stop_button = ttk.Button(
            button_frame,
            text="Stop",
            command=self.stop_scan,
            state='disabled'
        )
        self.stop_button.grid(row=0, column=1)
        
        # Progress Frame
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.StringVar(value="Ready to scan...")
        self.progress_label = ttk.Label(
            progress_frame,
            textvariable=self.progress_var,
            font=('Helvetica', 9)
        )
        self.progress_label.grid(row=0, column=0, sticky=tk.W)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            mode='indeterminate'
        )
        self.progress_bar.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # Results Frame
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.rowconfigure(3, weight=1)
        
        # Left panel
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)
        
        filter_frame = ttk.Frame(left_frame)
        filter_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        ttk.Label(filter_frame, text="Filter:").grid(row=0, column=0, padx=(0, 5))
        self.filter_var = tk.StringVar(value="All")
        self.filter_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.filter_var,
            values=["All", "Critical", "High", "Medium", "Low"],
            state='readonly',
            width=10
        )
        self.filter_combo.grid(row=0, column=1, padx=(0, 10))
        self.filter_combo.bind('<<ComboboxSelected>>', self.filter_vulnerabilities)
        
        # Vulnerabilities Treeview
        tree_frame = ttk.Frame(left_frame)
        tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(1, weight=1)
        
        self.tree = ttk.Treeview(
            tree_frame,
            columns=('Severity', 'Title'),
            show='headings',
            height=20
        )
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
        
        self.tree.tag_configure('critical', foreground=self.colors['critical'])
        self.tree.tag_configure('high', foreground=self.colors['high'])
        self.tree.tag_configure('medium', foreground=self.colors['medium'])
        self.tree.tag_configure('low', foreground=self.colors['low'])
        
        # Right panel
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=2)
        
        detail_label = ttk.Label(
            right_frame,
            text="Vulnerability Details",
            font=('Helvetica', 11, 'bold')
        )
        detail_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 5))
        
        self.detail_text = scrolledtext.ScrolledText(
            right_frame,
            wrap=tk.WORD,
            width=60,
            height=20,
            font=('Courier', 10)
        )
        self.detail_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)
        
        self.detail_text.tag_configure('critical', foreground=self.colors['critical'])
        self.detail_text.tag_configure('high', foreground=self.colors['high'])
        self.detail_text.tag_configure('medium', foreground=self.colors['medium'])
        self.detail_text.tag_configure('low', foreground=self.colors['low'])
        self.detail_text.tag_configure('bold', font=('Courier', 10, 'bold'))
        self.detail_text.tag_configure('heading', font=('Courier', 12, 'bold'))
        
        # Status bar
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(10, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        self.status_label = ttk.Label(
            status_frame,
            textvariable=self.status_var,
            font=('Helvetica', 9),
            foreground=self.colors['info']
        )
        self.status_label.grid(row=0, column=0, sticky=tk.W)
        
        self.export_button = ttk.Button(
            status_frame,
            text="Export to JSON",
            command=self.export_results,
            state='disabled'
        )
        self.export_button.grid(row=0, column=1, sticky=tk.E, padx=(0, 5))
        
        self.clear_button = ttk.Button(
            status_frame,
            text="Clear Results",
            command=self.clear_results
        )
        self.clear_button.grid(row=0, column=2, sticky=tk.E)
        
        status_frame.columnconfigure(0, weight=1)
        
        # Keyboard shortcuts
        self.root.bind('<Control-s>', lambda e: self.export_results())
    
    def check_for_updates_silent(self):
        """Check for updates silently on startup"""
        result = self.updater.check_for_update()
        
        if result and result.get('update_available'):
            self.root.after(500, lambda: self.show_update_dialog(result))
        else:
            self.status_var.set(f"Up to date (v{CURRENT_VERSION})")
    
    def manual_update_check(self):
        """Manual update check from menu"""
        self.status_var.set("Checking for updates...")
        result = self.updater.check_for_update()
        
        if result:
            if result.get('update_available'):
                self.show_update_dialog(result)
            else:
                self.show_update_dialog(result, up_to_date=True)
        else:
            messagebox.showinfo("Update Check", "Unable to check for updates.\nPlease check your internet connection.")
            self.status_var.set("Ready")
    
    def show_update_dialog(self, update_info, up_to_date=False):
        """Show update status dialog"""
        update_dialog = tk.Toplevel(self.root)
        
        if up_to_date:
            update_dialog.title("You're Up to Date!")
            dialog_height = 400
        else:
            update_dialog.title("Update Available!")
            dialog_height = 600
        
        update_dialog.geometry(f"500x{dialog_height}")
        update_dialog.configure(bg=self.colors['bg'])
        update_dialog.resizable(False, False)
        
        # Make it modal
        update_dialog.transient(self.root)
        update_dialog.grab_set()
        
        # Center on parent
        update_dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 500) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog_height) // 2
        update_dialog.geometry(f"+{x}+{y}")
        
        # Set icon
        try:
            icon_path = os.path.join(tempfile.gettempdir(), "it2_icon.ico")
            if os.path.exists(icon_path):
                update_dialog.iconbitmap(icon_path)
        except:
            pass
        
        if up_to_date:
            self.build_up_to_date_content(update_dialog, update_info)
        else:
            self.build_update_available_content(update_dialog, update_info)
    
    def build_up_to_date_content(self, dialog, update_info):
        """Build content for up-to-date dialog"""
        # Title
        tk.Label(
            dialog,
            text="You're Up to Date!",
            font=('Helvetica', 16, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['success']
        ).pack(pady=(30, 10))
        
        # Checkmark
        tk.Label(
            dialog,
            text="✓",
            font=('Helvetica', 48),
            bg=self.colors['bg'],
            fg=self.colors['success']
        ).pack(pady=10)
        
        # Info
        info_frame = tk.Frame(dialog, bg=self.colors['bg'])
        info_frame.pack(fill=tk.BOTH, padx=30, pady=10)
        
        tk.Label(
            info_frame,
            text=f"Current Version: v{update_info.get('current_version', CURRENT_VERSION)}",
            font=('Helvetica', 11),
            bg=self.colors['bg'],
            fg=self.colors['fg']
        ).pack(pady=5)
        
        tk.Label(
            info_frame,
            text=f"Latest Version: v{update_info.get('latest_version', CURRENT_VERSION)}",
            font=('Helvetica', 11),
            bg=self.colors['bg'],
            fg=self.colors['success']
        ).pack(pady=5)
        
        tk.Label(
            info_frame,
            text="No update is needed at this time.",
            font=('Helvetica', 10),
            bg=self.colors['bg'],
            fg=self.colors['fg']
        ).pack(pady=20)
        
        # Close button
        close_btn = tk.Button(
            dialog,
            text="Close",
            font=('Helvetica', 11),
            bg=self.colors['select_bg'],
            fg=self.colors['fg'],
            relief=tk.FLAT,
            padx=30,
            pady=10,
            cursor='hand2',
            command=dialog.destroy
        )
        close_btn.pack(pady=20)
    
    def build_update_available_content(self, dialog, update_info):
        """Build content for update available dialog"""
        # Title
        tk.Label(
            dialog,
            text="Update Available!",
            font=('Helvetica', 16, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['warning']
        ).pack(pady=(30, 10))
        
        # Warning icon
        tk.Label(
            dialog,
            text="⬆",
            font=('Helvetica', 48),
            bg=self.colors['bg'],
            fg=self.colors['warning']
        ).pack(pady=10)
        
        # Version info
        info_frame = tk.Frame(dialog, bg=self.colors['bg'])
        info_frame.pack(fill=tk.BOTH, padx=30, pady=10)
        
        tk.Label(
            info_frame,
            text="Current Version:",
            font=('Helvetica', 10, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['fg']
        ).pack(anchor=tk.W)
        
        tk.Label(
            info_frame,
            text=f"v{update_info['current_version']}",
            font=('Helvetica', 12),
            bg=self.colors['bg'],
            fg=self.colors['info']
        ).pack(anchor=tk.W, pady=(0, 10))
        
        tk.Label(
            info_frame,
            text="Latest Version:",
            font=('Helvetica', 10, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['fg']
        ).pack(anchor=tk.W)
        
        tk.Label(
            info_frame,
            text=f"v{update_info['latest_version']}",
            font=('Helvetica', 12),
            bg=self.colors['bg'],
            fg=self.colors['warning']
        ).pack(anchor=tk.W, pady=(0, 15))
        
        # Separator
        tk.Frame(info_frame, height=1, bg=self.colors['info']).pack(fill=tk.X, pady=10)
        
        # Release notes
        if update_info.get('release_notes'):
            tk.Label(
                info_frame,
                text="What's New:",
                font=('Helvetica', 10, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['fg']
            ).pack(anchor=tk.W, pady=(0, 5))
            
            notes_text = tk.Text(
                info_frame,
                height=8,
                width=55,
                font=('Helvetica', 9),
                bg=self.colors['select_bg'],
                fg=self.colors['fg'],
                relief=tk.FLAT,
                wrap=tk.WORD
            )
            notes_text.pack(fill=tk.BOTH, pady=(0, 10))
            notes_text.insert('1.0', update_info['release_notes'][:500])
            notes_text.config(state='disabled')
        
        # Auto update checkbox
        auto_update_var = tk.BooleanVar(value=True)
        auto_cb = tk.Checkbutton(
            info_frame,
            text="Auto-install after download",
            variable=auto_update_var,
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            selectcolor=self.colors['select_bg'],
            activebackground=self.colors['bg'],
            activeforeground=self.colors['fg']
        )
        auto_cb.pack(anchor=tk.W, pady=5)
        
        # Progress bar for download
        download_progress = ttk.Progressbar(
            info_frame,
            mode='determinate',
            length=400
        )
        download_progress.pack(fill=tk.X, pady=5)
        download_progress.pack_forget()  # Hidden initially
        
        progress_label = tk.Label(
            info_frame,
            text="",
            font=('Helvetica', 9),
            bg=self.colors['bg'],
            fg=self.colors['info']
        )
        progress_label.pack()
        progress_label.pack_forget()  # Hidden initially
        
        # Button frame
        button_frame = tk.Frame(dialog, bg=self.colors['bg'])
        button_frame.pack(pady=20)
        
        def update_now():
            """Download and optionally install the update"""
            download_btn.config(state='disabled')
            close_btn.config(state='disabled')
            
            download_progress.pack(fill=tk.X, pady=5)
            progress_label.pack()
            progress_label.config(text="Downloading update...")
            
            def progress_callback(percent):
                download_progress['value'] = percent
                progress_label.config(text=f"Downloading: {percent}%")
                dialog.update_idletasks()
            
            # Download in thread
            def download_thread():
                new_exe = self.updater.download_update(
                    update_info['download_url'],
                    progress_callback
                )
                
                if new_exe:
                    progress_label.config(text="Download complete!")
                    
                    if auto_update_var.get():
                        progress_label.config(text="Installing update...")
                        dialog.update_idletasks()
                        
                        if self.updater.install_update(new_exe):
                            progress_label.config(text="Update installed! Restarting...")
                            dialog.after(1500, self.root.quit)
                        else:
                            progress_label.config(text="Install failed. Please update manually.")
                            webbrowser.open(update_info['release_url'])
                    else:
                        progress_label.config(text="Download complete!")
                        messagebox.showinfo(
                            "Download Complete",
                            f"Update downloaded to:\n{new_exe}\n\nRun it to install the update.",
                            parent=dialog
                        )
                else:
                    progress_label.config(text="Download failed. Opening release page...")
                    webbrowser.open(update_info['release_url'])
                
                download_btn.config(state='normal')
                close_btn.config(state='normal')
            
            threading.Thread(target=download_thread, daemon=True).start()
        
        download_btn = tk.Button(
            button_frame,
            text="Update Now",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['button_bg'],
            fg=self.colors['button_fg'],
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor='hand2',
            command=update_now
        )
        download_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        close_btn = tk.Button(
            button_frame,
            text="Remind Later",
            font=('Helvetica', 11),
            bg=self.colors['select_bg'],
            fg=self.colors['fg'],
            relief=tk.FLAT,
            padx=20,
            pady=10,
            cursor='hand2',
            command=dialog.destroy
        )
        close_btn.pack(side=tk.LEFT)
    
    def show_about_dialog(self):
        """Show about dialog"""
        about_dialog = tk.Toplevel(self.root)
        about_dialog.title("About IT2Innovations Web IT Scan Tool")
        about_dialog.geometry("500x550")
        about_dialog.configure(bg=self.colors['bg'])
        about_dialog.resizable(False, False)
        
        # Make it modal
        about_dialog.transient(self.root)
        about_dialog.grab_set()
        
        # Center on parent
        about_dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - 500) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - 550) // 2
        about_dialog.geometry(f"+{x}+{y}")
        
        # Set icon
        try:
            icon_path = os.path.join(tempfile.gettempdir(), "it2_icon.ico")
            if os.path.exists(icon_path):
                about_dialog.iconbitmap(icon_path)
        except:
            pass
        
        # Title
        tk.Label(
            about_dialog,
            text="IT2Innovations Web IT Scan Tool",
            font=('Helvetica', 14, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['info']
        ).pack(pady=(30, 5))
        
        tk.Label(
            about_dialog,
            text=f"Version {CURRENT_VERSION}",
            font=('Helvetica', 11),
            bg=self.colors['bg'],
            fg=self.colors['fg']
        ).pack(pady=(0, 20))
        
        # Info frame
        info_frame = tk.Frame(about_dialog, bg=self.colors['bg'])
        info_frame.pack(fill=tk.BOTH, padx=40)
        
        # Creator info
        details = [
            ("Creator:", "Mike Larios"),
            ("Engineering Validation:", "Mike Larios"),
            ("License:", "MIT & Apache"),
            ("Repository:", f"github.com/{GITHUB_REPO}")
        ]
        
        for label, value in details:
            row_frame = tk.Frame(info_frame, bg=self.colors['bg'])
            row_frame.pack(fill=tk.X, pady=2)
            
            tk.Label(
                row_frame,
                text=label,
                font=('Helvetica', 10, 'bold'),
                bg=self.colors['bg'],
                fg=self.colors['fg']
            ).pack(side=tk.LEFT)
            
            tk.Label(
                row_frame,
                text=value,
                font=('Helvetica', 10),
                bg=self.colors['bg'],
                fg=self.colors['info']
            ).pack(side=tk.LEFT, padx=(5, 0))
        
        # Separator
        tk.Frame(info_frame, height=2, bg=self.colors['info']).pack(fill=tk.X, pady=15)
        
        # Legal warning
        tk.Label(
            info_frame,
            text="IMPORTANT LEGAL NOTICE",
            font=('Helvetica', 11, 'bold'),
            bg=self.colors['bg'],
            fg=self.colors['high']
        ).pack(pady=(5, 10))
        
        legal_text = (
            "This program is a testing tool, Pen Testing tool, "
            "and a tool used to exploit vulnerabilities of "
            "weakened or compromised websites.\n\n"
            "This can get you in trouble if you are not "
            "authorized by the site/ISP/Owner of the domain "
            "you are testing against.\n\n"
            "All legal ramifications will be on you, not any "
            "companies, persons, or devices mentioned in this "
            "file. We hold no legal or other responsible parts "
            "to the usage of this application.\n\n"
            "This is created and considered 'AS-IS' best "
            "effort coded."
        )
        
        tk.Label(
            info_frame,
            text=legal_text,
            font=('Helvetica', 9),
            bg=self.colors['bg'],
            fg=self.colors['fg'],
            wraplength=420,
            justify=tk.LEFT
        ).pack(pady=(0, 15))
        
        # Close button
        tk.Button(
            about_dialog,
            text="Close",
            font=('Helvetica', 11),
            bg=self.colors['select_bg'],
            fg=self.colors['fg'],
            relief=tk.FLAT,
            padx=30,
            pady=10,
            cursor='hand2',
            command=about_dialog.destroy
        ).pack(pady=(0, 20))
    
    def show_usage(self):
        """Show usage guide"""
        usage_text = (
            "USAGE GUIDE\n\n"
            "1. Enter the target URL in the input field\n"
            "2. Click 'Start Scan' to begin scanning\n"
            "3. Confirm that you have authorization to scan the target\n"
            "4. Wait for the scan to complete\n"
            "5. Review vulnerabilities in the left panel\n"
            "6. Click on vulnerabilities to see details\n"
            "7. Filter by severity using the dropdown\n"
            "8. Export results to JSON using the Export button\n\n"
            "FEATURES:\n"
            "• SSL/TLS Configuration Check\n"
            "• Security Headers Analysis\n"
            "• CORS Configuration Check\n"
            "• Information Disclosure Detection\n"
            "• Clickjacking Protection Check\n"
            "• XSS Protection Analysis\n"
            "• Cookie Security Check\n"
            "• Server Information Disclosure\n"
            "• Directory Listing Check\n"
            "• Form Security Analysis\n"
            "• Outdated Components Detection\n"
            "• CSRF Protection Check\n"
            "• SQL Injection Indicators\n\n"
            "AUTO-UPDATE:\n"
            "The tool automatically checks for updates on startup.\n"
            "When an update is available, you'll see a dialog with\n"
            "the option to download and install the update automatically.\n\n"
            "For more information, visit our GitHub repository."
        )
        
        messagebox.showinfo("Usage Guide", usage_text)
    
    def start_scan(self):
        """Start the security scan"""
        url = self.target_url.get().strip()
        
        if not url:
            messagebox.showwarning("No URL", "Please enter a target URL to scan.")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
            self.target_url.set(url)
        
        # Show authorization warning
        warning_msg = (
            "LEGAL WARNING\n\n"
            "This program is a testing tool, Pen Testing tool, and a tool used\n"
            "to exploit vulnerabilities of weakened or compromised websites.\n\n"
            "This can get you in trouble if you are not authorized by the\n"
            "site/ISP/Owner of the domain you are testing against.\n\n"
            "All legal ramifications will be on you, not any companies, persons,\n"
            "or devices mentioned in this file.\n\n"
            "Do you have explicit authorization to scan this target?"
        )
        
        if not messagebox.askyesno("Authorization Required", warning_msg, icon='warning'):
            return
        
        self.clear_results()
        
        self.scan_button.config(state='disabled')
        self.stop_button.config(state='normal')
        self.export_button.config(state='disabled')
        self.url_entry.config(state='disabled')
        self.filter_combo.config(state='disabled')
        
        self.progress_bar.start(10)
        self.progress_var.set("Initializing scanner...")
        self.status_var.set("Scanning...")
        
        self.scanning = True
        scan_thread = threading.Thread(target=self.run_scan, args=(url,))
        scan_thread.daemon = True
        scan_thread.start()
    
    def run_scan(self, url):
        """Run scan in thread"""
        try:
            self.scanner = SecurityScanner(
                url,
                progress_callback=self.update_progress
            )
            self.scanner.scan()
            self.root.after(0, self.scan_complete)
        except Exception as e:
            self.root.after(0, self.scan_error, str(e))
    
    def update_progress(self, message):
        """Update progress from thread"""
        self.root.after(0, lambda: self.progress_var.set(message))
        self.root.after(0, lambda: self.status_var.set(message))
    
    def scan_complete(self):
        """Scan completion handler"""
        self.progress_bar.stop()
        self.progress_var.set(f"Scan complete! Found {len(self.scanner.vulnerabilities)} vulnerabilities.")
        self.status_var.set(f"Found {len(self.scanner.vulnerabilities)} vulnerabilities")
        
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.export_button.config(state='normal')
        self.url_entry.config(state='normal')
        self.filter_combo.config(state='readonly')
        
        self.populate_tree()
        self.scanning = False
    
    def scan_error(self, error_msg):
        """Error handler"""
        self.progress_bar.stop()
        self.progress_var.set(f"Error: {error_msg}")
        self.status_var.set("Scan failed")
        
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.url_entry.config(state='normal')
        self.filter_combo.config(state='readonly')
        
        self.scanning = False
        
        messagebox.showerror("Scan Error", f"An error occurred during the scan:\n\n{error_msg}")
    
    def stop_scan(self):
        """Stop scan"""
        self.scanning = False
        self.progress_bar.stop()
        self.progress_var.set("Scan stopped by user")
        self.status_var.set("Stopped")
        
        self.scan_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.url_entry.config(state='normal')
        self.filter_combo.config(state='readonly')
    
    def populate_tree(self, filter_severity="All"):
        """Populate vulnerabilities tree"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        if not self.scanner:
            return
        
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        sorted_vulns = sorted(
            self.scanner.vulnerabilities,
            key=lambda x: severity_order.get(x['severity'].upper(), 4)
        )
        
        for vuln in sorted_vulns:
            if filter_severity == "All" or vuln['severity'].upper() == filter_severity.upper():
                severity_tag = vuln['severity'].lower()
                self.tree.insert(
                    '',
                    'end',
                    values=(vuln['severity'], vuln['title']),
                    tags=(severity_tag,)
                )
    
    def filter_vulnerabilities(self, event=None):
        """Filter by severity"""
        self.populate_tree(self.filter_var.get())
    
    def on_vulnerability_select(self, event):
        """Display vulnerability details"""
        selection = self.tree.selection()
        if not selection:
            return
        
        item = self.tree.item(selection[0])
        title = item['values'][1]
        
        vuln = None
        if self.scanner:
            for v in self.scanner.vulnerabilities:
                if v['title'] == title:
                    vuln = v
                    break
        
        if vuln:
            self.display_vulnerability_details(vuln)
    
    def display_vulnerability_details(self, vuln):
        """Show vulnerability details"""
        self.detail_text.delete('1.0', tk.END)
        
        severity_tag = vuln['severity'].lower()
        
        self.detail_text.insert(tk.END, "VULNERABILITY DETAILS\n", 'heading')
        self.detail_text.insert(tk.END, "-" * 50 + "\n\n")
        
        self.detail_text.insert(tk.END, "Title: ", 'bold')
        self.detail_text.insert(tk.END, f"{vuln['title']}\n\n")
        
        self.detail_text.insert(tk.END, "Severity: ", 'bold')
        self.detail_text.insert(tk.END, f"{vuln['severity']}\n", severity_tag)
        self.detail_text.insert(tk.END, "\n")
        
        self.detail_text.insert(tk.END, "Location:\n", 'bold')
        self.detail_text.insert(tk.END, f"  {vuln['location']}\n\n")
        
        self.detail_text.insert(tk.END, "Description:\n", 'bold')
        self.detail_text.insert(tk.END, f"  {vuln['description']}\n\n")
        
        if vuln['evidence']:
            self.detail_text.insert(tk.END, "Evidence:\n", 'bold')
            self.detail_text.insert(tk.END, f"  {vuln['evidence']}\n\n")
        
        self.detail_text.insert(tk.END, "Recommended Fix:\n", 'bold')
        self.detail_text.insert(tk.END, f"  {vuln['fix']}\n\n")
        
        self.detail_text.insert(tk.END, "Detected at:\n", 'bold')
        self.detail_text.insert(tk.END, f"  {vuln['timestamp']}\n")
        
        self.detail_text.see('1.0')
    
    def export_results(self):
        """Export to JSON"""
        if not self.scanner or not self.scanner.vulnerabilities:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        default_filename = f"security_scan_{self.scanner.base_domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile=default_filename,
            title="Export Scan Results"
        )
        
        if not filename:
            return
        
        try:
            self.scanner.export_to_json(filename)
            
            if messagebox.askyesno(
                "Export Complete",
                f"Results exported successfully to:\n{filename}\n\nWould you like to open the file?",
                icon='info'
            ):
                os.startfile(filename)
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n\n{str(e)}")
    
    def clear_results(self):
        """Clear all results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.detail_text.delete('1.0', tk.END)
        self.progress_var.set("Ready to scan...")
        self.status_var.set("Ready")
        self.export_button.config(state='disabled')
        self.scanner = None

def main():
    root = tk.Tk()
    
    # Set AppUserModelID before creating the window (Windows taskbar icon fix)
    if sys.platform == 'win32':
        try:
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                'IT2Innovations.WebITScanTool.1.0'
            )
        except:
            pass
    
    app = SecurityScannerGUI(root)
    
    # Center window
    root.update_idletasks()
    width = 1200
    height = 800
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()