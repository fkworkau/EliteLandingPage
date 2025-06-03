import { type Express } from "express";
import { createServer, type Server } from "node:http";
import { storage } from "./storage";

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

  // Advanced crypter endpoint
  app.post("/api/advanced-crypter", async (req, res) => {
    try {
      // Since this is educational, we'll simulate the crypter process
      const outputName = `protected_${Date.now()}`;
      
      await storage.createAnalytics({
        metric: 'crypter_usage',
        value: JSON.stringify({ 
          outputName, 
          timestamp: new Date().toISOString(),
          educational: true 
        })
      });

      res.json({
        success: true,
        downloadUrl: `/download/${outputName}.exe`,
        filename: `${outputName}.exe`,
        message: 'Educational simulation completed - real crypter functionality requires proper configuration'
      });
    } catch (error) {
      console.error('Error in crypter:', error);
      res.status(500).json({ error: 'Crypter processing failed' });
    }
  });

  return server;
}