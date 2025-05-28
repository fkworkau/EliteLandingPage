import type { Express } from "express";
import { createServer, type Server } from "http";
import { Server as SocketIOServer } from "socket.io";
import bcrypt from "bcrypt";
import session from "express-session";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";
import { insertAdminUserSchema, insertVisitorSchema, insertPacketLogSchema, insertAnalyticsSchema } from "@shared/schema";

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

  // Setup session middleware
  app.use(getSession());

  // IP geolocation service (educational simulation)
  async function getLocationData(ip: string) {
    try {
      // Check if we have API rate limits, use educational simulation instead
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      if (!response.ok) {
        throw new Error('API rate limit exceeded');
      }
      const data = await response.json();
      
      // Check if response contains error message (rate limiting)
      if (data.error || typeof data === 'string') {
        throw new Error('Rate limited');
      }
      
      return {
        country: data.country_name || "Unknown",
        city: data.city || "Unknown",
        latitude: data.latitude?.toString() || null,
        longitude: data.longitude?.toString() || null,
      };
    } catch (error) {
      console.error("Geolocation API error:", error);
      // Return educational simulation data when API fails
      return {
        country: "Educational Lab",
        city: "Training Environment",
        latitude: "40.7128",
        longitude: "-74.0060",
      };
    }
  }

  // Visitor tracking middleware
  app.use(async (req: any, res, next) => {
    try {
      const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress || req.ip;
      const userAgent = req.headers['user-agent'];
      const sessionId = req.sessionID;

      // Skip tracking for admin routes and assets
      if (req.path.startsWith('/api/admin') || req.path.startsWith('/assets')) {
        return next();
      }

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

      // Emit real-time visitor data
      io.emit('newVisitor', visitor);

      // Update analytics
      await storage.createAnalytics({
        metric: 'page_view',
        value: req.path,
      });

    } catch (error) {
      console.error("Visitor tracking error:", error);
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
      res.json({ id: admin.id, username: admin.username });
    } catch (error) {
      res.status(500).json({ message: "Failed to fetch admin data" });
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

  // Cookie consent tracking
  app.post("/api/cookie-consent", async (req: any, res) => {
    try {
      const { consent } = req.body;
      
      await storage.createAnalytics({
        metric: 'cookie_consent',
        value: consent ? 'accepted' : 'declined',
      });

      res.json({ message: "Consent recorded" });
    } catch (error) {
      res.status(500).json({ message: "Failed to record consent" });
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
