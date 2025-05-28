import { useState, useEffect } from 'react';
import { Shield, Activity, Eye, Zap } from 'lucide-react';
import AdminLoginModal from '@/components/admin-login-modal';
import CookieBanner from '@/components/cookie-banner';

export default function Landing() {
  const [showAdminModal, setShowAdminModal] = useState(false);
  const [visitorCount, setVisitorCount] = useState(0);

  useEffect(() => {
    // Track visitor
    fetch('/api/visitor-tracking', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userAgent: navigator.userAgent,
        referrer: document.referrer,
        language: navigator.language,
        screenResolution: `${screen.width}x${screen.height}`,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
      })
    }).then(res => res.json())
      .then(data => setVisitorCount(data.totalVisitors || 0))
      .catch(console.error);

    console.log('Educational tracking simulation started');
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800 text-white relative overflow-x-hidden">
      {/* Admin Access (Hidden) */}
      <div className="absolute top-4 right-4 z-50">
        <button
          onClick={() => setShowAdminModal(true)}
          className="text-gray-600 hover:text-matrix transition-colors opacity-30 hover:opacity-100"
          title="Admin Access"
        >
          <Shield size={20} />
        </button>
      </div>

      {/* Visitor Counter */}
      <div className="absolute top-4 left-4 text-xs text-gray-500 font-mono">
        <Activity size={12} className="inline mr-1" />
        {visitorCount} visitors
      </div>

      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <header className="text-center mb-12">
          <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-mono font-bold mb-4 relative text-matrix glow-pulse">
            MILLENNIUM REMOTE ADMIN TOOLS
          </h1>
          <p className="font-mono text-xl text-gray-400 typing-animation">
            Professional Network Administration Suite
          </p>
        </header>

        {/* Main Content */}
        <section className="rounded-lg border border-matrix p-6 max-w-4xl mx-auto mb-8">
          <div className="text-center">
            <p className="text-gray-300 mb-6 text-lg leading-relaxed">
              Welcome to the ultimate collection of network administration tools, crafted for professionals. From remote access to system monitoring, our tools are designed to manage any network with precision and reliability. Each tool is built for performance, security, and ease of use. Join the ranks of the best—get yours today.
            </p>
            <a 
              href="#contact" 
              className="inline-block bg-matrix hover:bg-matrix/80 text-black px-8 py-3 rounded-lg font-mono mb-4 transition-all duration-300 hover:scale-105 shadow-lg"
            >
              Contact Sales Team
            </a>
            <p className="text-gray-400 text-sm font-mono">
              Enterprise Solutions | Professional Support | Secure Payments
            </p>
          </div>
        </section>

        {/* Educational Tools Panel */}
        <section className="bg-gray-800 rounded-lg border border-matrix/30 p-8 mb-8">
          <h2 className="text-3xl font-bold text-center mb-4 text-matrix">Blue Team Training Tools</h2>
          <p className="text-gray-300 text-center mb-6 text-lg">
            Comprehensive cybersecurity education platform for defensive security training. Practice threat detection, incident response, and network monitoring in a controlled environment.
          </p>
          
          <div className="grid md:grid-cols-3 gap-6 mb-8">
            {/* Network Monitoring */}
            <div className="terminal-window p-4">
              <div className="terminal-header">
                <div className="terminal-dot terminal-dot-red"></div>
                <div className="terminal-dot terminal-dot-yellow"></div>
                <div className="terminal-dot terminal-dot-green"></div>
                <span className="text-xs font-mono ml-2">network_monitor.exe</span>
              </div>
              <div className="p-4">
                <h3 className="text-matrix font-mono text-lg mb-2">Network Monitor</h3>
                <p className="text-gray-400 text-sm mb-3">Real-time network traffic analysis and packet inspection tools</p>
                <button className="cyber-button w-full">Launch Monitor</button>
              </div>
            </div>

            {/* Threat Detection */}
            <div className="terminal-window p-4">
              <div className="terminal-header">
                <div className="terminal-dot terminal-dot-red"></div>
                <div className="terminal-dot terminal-dot-yellow"></div>
                <div className="terminal-dot terminal-dot-green"></div>
                <span className="text-xs font-mono ml-2">threat_detect.exe</span>
              </div>
              <div className="p-4">
                <h3 className="text-matrix font-mono text-lg mb-2">Threat Detection</h3>
                <p className="text-gray-400 text-sm mb-3">AI-powered threat analysis and behavioral detection</p>
                <button className="cyber-button w-full">Start Analysis</button>
              </div>
            </div>

            {/* Incident Response */}
            <div className="terminal-window p-4">
              <div className="terminal-header">
                <div className="terminal-dot terminal-dot-red"></div>
                <div className="terminal-dot terminal-dot-yellow"></div>
                <div className="terminal-dot terminal-dot-green"></div>
                <span className="text-xs font-mono ml-2">incident_resp.exe</span>
              </div>
              <div className="p-4">
                <h3 className="text-matrix font-mono text-lg mb-2">Incident Response</h3>
                <p className="text-gray-400 text-sm mb-3">Forensic analysis and threat containment protocols</p>
                <button className="cyber-button w-full">Access Console</button>
              </div>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="text-matrix font-mono mb-3">Training Modules</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start"><span className="text-matrix mr-2">📚</span>Network Security Fundamentals</li>
                <li className="flex items-start"><span className="text-matrix mr-2">📚</span>Malware Analysis Techniques</li>
                <li className="flex items-start"><span className="text-matrix mr-2">📚</span>Digital Forensics Procedures</li>
                <li className="flex items-start"><span className="text-matrix mr-2">📚</span>Vulnerability Assessment</li>
                <li className="flex items-start"><span className="text-matrix mr-2">📚</span>Security Incident Handling</li>
                <li className="flex items-start"><span className="text-matrix mr-2">📚</span>Threat Intelligence Analysis</li>
              </ul>
            </div>
            <div>
              <h4 className="text-matrix font-mono mb-3">Lab Environments</h4>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start"><span className="text-matrix mr-2">🔬</span>Isolated Virtual Networks</li>
                <li className="flex items-start"><span className="text-matrix mr-2">🔬</span>Real-time Attack Simulations</li>
                <li className="flex items-start"><span className="text-matrix mr-2">🔬</span>SIEM Dashboard Training</li>
                <li className="flex items-start"><span className="text-matrix mr-2">🔬</span>Network Traffic Analysis</li>
                <li className="flex items-start"><span className="text-matrix mr-2">🔬</span>Malware Sandbox Testing</li>
                <li className="flex items-start"><span className="text-matrix mr-2">🔬</span>Incident Response Drills</li>
              </ul>
            </div>
          </div>
        </section>

        {/* DotStealer Section */}
        <section className="bg-gray-800 rounded-lg border border-gray-700 p-8 mb-8">
          <h2 className="text-3xl font-bold text-center mb-4 text-matrix">DotStealer</h2>
          <p className="text-gray-300 text-center mb-6 text-lg">
            A multifunctional Windows stealer that sends logs via Telegram bot—no dedicated server needed. Lifetime license for only $30 (updates included). Stay updated via my Telegram channel.
          </p>
          
          <div className="flex justify-center mb-6">
            <div className="max-w-md">
              <img 
                src="https://i.ibb.co/mCnkNsTt/432992187-f48c474b-1e68-4f7d-ba6e-14ad01afdcf4.png" 
                alt="DotStealer Builder" 
                className="w-full rounded-lg border border-gray-600 shadow-lg"
              />
              <p className="text-center text-sm text-gray-400 mt-2 font-mono">DotStealer - Configuration Panel</p>
            </div>
          </div>

          <div className="text-center mb-6">
            <a 
              href="https://t.me/shinyenigma" 
              target="_blank" 
              className="inline-block bg-red-600 hover:bg-red-700 text-white px-8 py-3 rounded-lg font-mono transition-all duration-300 hover:scale-105 shadow-lg"
            >
              Buy Now
            </a>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <ul className="space-y-2 text-sm">
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>NEW: Significantly decreased file size</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>NEW: Grabs complete list of installed software</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Easy-to-use compact builder</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Client works on Windows 7+ (32/64-bit)</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Anti double-launch protection</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Anti-VM and Anti-Debug for evasion</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Single .NET exe, no dependencies</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Two types of data encryption</li>
            </ul>
            <ul className="space-y-2 text-sm">
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Grabs desktop files</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Run from start directory or install</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Browser data stealing (cookies, downloads, passwords, etc.)</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>App-Bound cookie protection bypass (no admin privileges)</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Discord token grabbing</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Telegram session grabbing</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Desktop screenshot capture</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Metamask and Exodus data stealing</li>
            </ul>
          </div>
        </section>

        {/* Vedani-Crypter Section */}
        <section className="bg-gray-800 rounded-lg border border-gray-700 p-8 mb-8">
          <h2 className="text-3xl font-bold text-center mb-4 text-matrix">Vedani-Crypter</h2>
          <p className="text-gray-300 text-center mb-6 text-lg">
            A renowned private Runtime & Scantime crypter with an updating stub and lifetime license—available for free. Protect your EXE files from antivirus scans with this powerful tool, complete with a video tutorial.
          </p>
          
          <div className="flex justify-center mb-6">
            <div className="max-w-md">
              <img 
                src="https://i.ibb.co/BK3SgSQX/56c2nd8g.png" 
                alt="Vedani-Crypter Interface" 
                className="w-full rounded-lg border border-gray-600 shadow-lg"
              />
              <p className="text-center text-sm text-gray-400 mt-2 font-mono">Vedani-Crypter - Main Interface</p>
            </div>
          </div>

          <div className="text-center mb-6">
            <a 
              href="https://github.com/ardentus/Vedani-Crypter.git" 
              target="_blank" 
              className="inline-block bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg font-mono transition-all duration-300 hover:scale-105 shadow-lg"
            >
              Download Vedani-Crypter
            </a>
          </div>

          <ul className="space-y-2 text-sm max-w-2xl mx-auto">
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Runtime & Scantime crypter for EXE protection</li>
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Updating stub for continuous effectiveness</li>
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Lifetime license, free to use</li>
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Includes a video tutorial for setup</li>
          </ul>
        </section>

        {/* VBS Binder Section */}
        <section className="bg-gray-800 rounded-lg border border-gray-700 p-8 mb-8">
          <h2 className="text-3xl font-bold text-center mb-4 text-matrix">VBS Binder</h2>
          <p className="text-gray-300 text-center mb-6 text-lg">
            A cutting-edge VBS binder generator that runs non-crypted builds without detection by Windows Defender. Adds Defender exclusions, downloads, and executes files while avoiding SmartScreen alerts.
          </p>
          
          <div className="flex justify-center mb-6">
            <div className="max-w-md">
              <img 
                src="https://i.ibb.co/HDTpGjZ4/433060068-33a9d53e-05eb-46f0-8870-826cf9e0643d.png" 
                alt="VBS Binder Interface" 
                className="w-full rounded-lg border border-gray-600 shadow-lg"
              />
              <p className="text-center text-sm text-gray-400 mt-2 font-mono">VBS Binder - Generator Interface</p>
            </div>
          </div>

          <div className="text-center mb-6">
            <a 
              href="https://t.me/shinyenigma" 
              target="_blank" 
              className="inline-block bg-red-600 hover:bg-red-700 text-white px-8 py-3 rounded-lg font-mono transition-all duration-300 hover:scale-105 shadow-lg"
            >
              Buy Now
            </a>
          </div>

          <ul className="space-y-2 text-sm max-w-2xl mx-auto">
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Random obfuscation for every generated file</li>
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>No SmartScreen alerts for binder or downloaded files</li>
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>No Windows Defender alerts</li>
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Bind multiple files with ease</li>
            <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Optional fake error for deception</li>
          </ul>
        </section>

        {/* LNK Exploit Builder Section */}
        <section className="bg-gray-800 rounded-lg border border-gray-700 p-8 mb-8">
          <h2 className="text-3xl font-bold text-center mb-4 text-matrix">LNK Exploit Builder</h2>
          <p className="text-gray-300 text-center mb-6 text-lg">
            An advanced exploit that generates a fake .txt file with a backdoor to execute EXE/BAT files silently. Designed for Windows 7 and higher, perfect for stealth operations.
          </p>
          
          <div className="flex justify-center mb-6">
            <div className="max-w-md">
              <img 
                src="https://i.ibb.co/8LC2Rsr6/426710183-82256fed-fe27-481b-ac6a-d0fbf9701882.png" 
                alt="LNK Exploit Builder Interface" 
                className="w-full rounded-lg border border-gray-600 shadow-lg"
              />
              <p className="text-center text-sm text-gray-400 mt-2 font-mono">LNK Exploit Builder - Main Interface</p>
            </div>
          </div>

          <div className="text-center mb-6">
            <a 
              href="https://github.com/shinyelectron/LNK-Exploit.git" 
              target="_blank" 
              className="inline-block bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg font-mono transition-all duration-300 hover:scale-105 shadow-lg"
            >
              Download LNK Exploit Builder
            </a>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <ul className="space-y-2 text-sm">
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>NEW: Additional link encoding and obfuscation</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Easy-to-use builder</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Fake description generator</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Hides backdoor code deep inside the binary</li>
            </ul>
            <ul className="space-y-2 text-sm">
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Txt downloading option for long text files</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Silent PowerShell console in the background</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Anti-analyzing: Property changes disable malicious code</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Bypasses Windows SmartScreen alerts</li>
            </ul>
          </div>
        </section>

        {/* 888 RAT Section */}
        <section className="bg-gray-800 rounded-lg border border-gray-700 p-8 mb-8">
          <h2 className="text-3xl font-bold text-center mb-4 text-matrix">888 RAT (Windows/Android/Linux)</h2>
          <p className="text-gray-300 text-center mb-6 text-lg">
            An advanced hidden remote access tool, available for free, with modes for Android, Windows, and Linux. Dominate across platforms with this versatile RAT. Archive password: 888.
          </p>
          
          <div className="flex justify-center mb-6">
            <div className="max-w-md">
              <img 
                src="https://i.ibb.co/9JMcNGy/426647492-039db33a-8d20-4607-8991-52c4dcbdd9fa.png" 
                alt="888 RAT Interface" 
                className="w-full rounded-lg border border-gray-600 shadow-lg"
              />
              <p className="text-center text-sm text-gray-400 mt-2 font-mono">888 RAT - Settings</p>
            </div>
          </div>

          <div className="text-center mb-6">
            <a 
              href="https://mega.nz/file/d6V1kB5C#snmOatmYcYDz4I7T4coGEElM7kyhU9prWE873FI8wz8" 
              target="_blank" 
              className="inline-block bg-green-600 hover:bg-green-700 text-white px-8 py-3 rounded-lg font-mono transition-all duration-300 hover:scale-105 shadow-lg"
            >
              Download 888 RAT
            </a>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <ul className="space-y-2 text-sm">
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Anti-Analysis for stealth operation</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Icon Changer for customization</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Startup Sleep for delayed execution</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Fake error for deception</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>VBS exploit integration</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Supports Windows, Android, and Linux</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>File system access</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Spy features: desktop, webcam, system sound</li>
            </ul>
            <ul className="space-y-2 text-sm">
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Stealer: passwords, cookies, FileZilla, etc.</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>CMD, regedit, get installed software</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Network scanner, hidden RDP, DNS Spoof</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>PC info, GeoIP, Internet Speed Test, Open URL</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Kill/Uninstall functionality</li>
              <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>And much more</li>
            </ul>
          </div>
        </section>
      </div>

      {/* Educational Footer */}
      <div className="fixed bottom-0 w-full bg-black/90 px-2 py-1 text-center text-xs text-black opacity-20">
        Educational cybersecurity simulation platform for defensive training purposes
      </div>

      {/* Admin Modal */}
      <AdminLoginModal 
        open={showAdminModal} 
        onOpenChange={setShowAdminModal}
        onSuccess={() => window.location.href = '/admin'}
      />

      {/* Cookie Banner */}
      <CookieBanner />
    </div>
  );
}