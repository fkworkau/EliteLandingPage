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

  // IP geolocation service (using ipapi.co)
  async function getLocationData(ip: string) {
    try {
      const response = await fetch(`https://ipapi.co/${ip}/json/`);
      const data = await response.json();
      return {
        country: data.country_name || "Unknown",
        city: data.city || "Unknown",
        latitude: data.latitude?.toString() || null,
        longitude: data.longitude?.toString() || null,
      };
    } catch (error) {
      console.error("Geolocation API error:", error);
      return {
        country: "Unknown",
        city: "Unknown",
        latitude: null,
        longitude: null,
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

  // AI content modification (placeholder for Groq integration)
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
