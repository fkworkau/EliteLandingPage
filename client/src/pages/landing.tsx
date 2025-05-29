
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
    <div className="min-h-screen bg-black text-blue-300 overflow-x-hidden">
      <div className="container max-w-7xl mx-auto px-5 py-8 bg-gray-900 rounded-lg">
        <header className="text-center py-12">
          <h1 className="text-5xl md:text-6xl text-blue-400 tracking-wide mb-3 font-bold">
            Elite Hacking Tools
          </h1>
          <p className="text-xl md:text-2xl text-gray-400">
            Unleash Your Power with Premium Cyber Weapons
          </p>
        </header>

        <section className="py-8 text-center bg-gray-800 rounded-lg my-5">
          <p className="text-lg md:text-xl leading-relaxed text-blue-300 mb-6">
            Welcome to the ultimate collection of hacking tools, crafted for the elite. From remote access to stealth data extraction, our tools are designed to dominate any system with precision and style. Each tool is built for performance, stealth, and ease of use. Join the ranks of the best—get yours today.
          </p>
          
          <div className="flex items-center justify-center gap-4 mb-6">
            <Badge variant="secondary" className="bg-red-900 text-red-300 text-base px-4 py-2">
              <Activity className="w-4 h-4 mr-2" />
              {visitorCount} Active Users
            </Badge>
            <Badge variant="secondary" className="bg-green-900 text-green-300 text-base px-4 py-2">
              <Users className="w-4 h-4 mr-2" />
              Live Now
            </Badge>
          </div>

          <a 
            href="https://t.me/shinyenigma" 
            target="_blank" 
            rel="noopener noreferrer"
            className="inline-block mx-3 my-4 px-6 py-3 bg-blue-500 text-white text-lg font-medium rounded-lg hover:bg-blue-600 transition-all duration-300 hover:translate-y-[-1px] hover:shadow-lg hover:shadow-blue-500/20"
          >
            Contact via Telegram: @shinyenigma
          </a>
          
          <p className="text-gray-300 mt-4">Payments: USDT, BTC, TRX, XMR, ETH, LTC, and more</p>
        </section>

        <section className="py-8 bg-gray-800 rounded-lg my-5">
          <h2 className="text-3xl md:text-4xl text-center mb-4 text-blue-400 font-bold">
            Millennium RAT v4.0
          </h2>
          <p className="text-lg text-center text-gray-300 mb-4">
            A battle-tested Remote Access Tool with a 2-year legacy, now fully rewritten in C++ for unmatched performance. Control via Telegram with no server or port forwarding needed. Steal data, log keys, and own systems effortlessly.
          </p>
          
          <div className="flex justify-center mb-5">
            <div className="relative max-w-md w-full border border-gray-700 rounded-lg hover:translate-y-[-3px] transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/10">
              <img 
                src="https://i.ibb.co/PZSZ98XD/8g4be4sa.png" 
                alt="Millennium RAT Builder" 
                className="w-full rounded-lg"
              />
              <div className="absolute bottom-2 left-0 right-0 text-center bg-black/60 text-blue-300 py-1.5 text-sm rounded-b-lg">
                Millennium RAT - Control Panel
              </div>
            </div>
          </div>

          <div className="text-center mb-5">
            <a 
              href="https://t.me/shinyenigma" 
              target="_blank" 
              rel="noopener noreferrer"
              className="inline-block mx-3 my-4 px-6 py-3 bg-blue-500 text-white text-lg font-medium rounded-lg hover:bg-blue-600 transition-all duration-300 hover:translate-y-[-1px] hover:shadow-lg hover:shadow-blue-500/20"
            >
              Buy Now
            </a>
            <Button
              variant="outline"
              size="lg"
              className="border-blue-400 text-blue-400 hover:bg-blue-400 hover:text-black px-6 py-3 text-lg font-medium ml-4"
              onClick={() => setShowAdminLogin(true)}
            >
              Admin Portal
            </Button>
          </div>

          <ul className="list-none px-5 space-y-2">
            {[
              "Fully rewritten in C++ for speed and stealth",
              "Small native executable, zero dependencies", 
              "No Microsoft Visual C++ required",
              "Works on Windows 7+ (32/64-bit)",
              "Auto StartUp for persistent access",
              "Anti double-launch protection",
              "AutoStealer for effortless data theft",
              "Keylogger for capturing every keystroke",
              "Anti-VM and Anti-Debug for ultimate evasion",
              "Compact, user-friendly builder",
              "Self-installing or non-installing options",
              "Auto command execution on first run",
              "Adjustable startup/request delay",
              "Remote PowerShell/CMD execution",
              "System info grabbing (CPU, GPU, RAM, location, IP, MAC)",
              "Discord token theft (client and browsers)",
              "Telegram data extraction",
              "Browser data theft (downloads, cookies, passwords, credit cards, history)",
              "Crypto wallet recovery",
              "Webcamera capture for surveillance",
              "Privilege elevation for deeper control",
              "Messageboxes, wallpaper changes, display rotation",
              "One-command desktop file grabbing",
              "File encryption/decryption",
              "Window minimize/maximize control"
            ].map((feature, index) => (
              <li key={index} className="text-blue-300 relative pl-6 hover:text-blue-400 transition-colors duration-300">
                <span className="absolute left-0 text-blue-400 text-lg">✔️</span>
                {feature}
              </li>
            ))}
          </ul>
        </section>

        <section className="py-8 bg-gray-800 rounded-lg my-5">
          <h2 className="text-3xl md:text-4xl text-center mb-4 text-blue-400 font-bold">
            DotStealer
          </h2>
          <p className="text-lg text-center text-gray-300 mb-4">
            A multifunctional Windows stealer that sends logs via Telegram bot—no dedicated server needed. Lifetime license for only $30 (updates included). Stay updated via my Telegram channel.
          </p>
          
          <div className="flex justify-center mb-5">
            <div className="relative max-w-md w-full border border-gray-700 rounded-lg hover:translate-y-[-3px] transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/10">
              <img 
                src="https://i.ibb.co/mCnkNsTt/432992187-f48c474b-1e68-4f7d-ba6e-14ad01afdcf4.png" 
                alt="DotStealer Builder" 
                className="w-full rounded-lg"
              />
              <div className="absolute bottom-2 left-0 right-0 text-center bg-black/60 text-blue-300 py-1.5 text-sm rounded-b-lg">
                DotStealer - Configuration Panel
              </div>
            </div>
          </div>

          <div className="text-center mb-5">
            <a 
              href="https://t.me/shinyenigma" 
              target="_blank" 
              rel="noopener noreferrer"
              className="inline-block mx-3 my-4 px-6 py-3 bg-blue-500 text-white text-lg font-medium rounded-lg hover:bg-blue-600 transition-all duration-300 hover:translate-y-[-1px] hover:shadow-lg hover:shadow-blue-500/20"
            >
              Buy Now
            </a>
          </div>

          <ul className="list-none px-5 space-y-2">
            {[
              "NEW: Significantly decreased file size",
              "NEW: Grabs complete list of installed software",
              "Easy-to-use compact builder",
              "Client works on Windows 7+ (32/64-bit)",
              "Anti double-launch protection",
              "Anti-VM and Anti-Debug for evasion",
              "Single .NET exe, no dependencies",
              "Two types of data encryption",
              "Grabs desktop files",
              "Run from start directory or install",
              "Browser data stealing (cookies, downloads, passwords, etc.)",
              "App-Bound cookie protection bypass (no admin privileges)",
              "Discord token grabbing",
              "Telegram session grabbing",
              "Desktop screenshot capture",
              "Metamask and Exodus data stealing",
              "System info stealing (IP, location, username, RAM, GPU, HWID, etc.)"
            ].map((feature, index) => (
              <li key={index} className="text-blue-300 relative pl-6 hover:text-blue-400 transition-colors duration-300">
                <span className="absolute left-0 text-blue-400 text-lg">✔️</span>
                {feature}
              </li>
            ))}
          </ul>
        </section>

        <section className="py-8 bg-gray-800 rounded-lg my-5">
          <h2 className="text-3xl md:text-4xl text-center mb-4 text-blue-400 font-bold">
            FREE Vedani-Crypter + Bonus Tools
          </h2>
          <p className="text-lg text-center text-gray-300 mb-4">
            Get our renowned private Runtime & Scantime crypter with updating stub and lifetime license—available for FREE! Plus exclusive bonus tools for early adopters. Protect your files from antivirus detection.
          </p>
          
          <div className="flex justify-center gap-4 flex-wrap mb-5">
            <div className="relative max-w-sm w-full border border-gray-700 rounded-lg hover:translate-y-[-3px] transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/10">
              <img 
                src="https://i.ibb.co/BK3SgSQX/56c2nd8g.png" 
                alt="Vedani-Crypter Interface" 
                className="w-full rounded-lg"
              />
              <div className="absolute bottom-2 left-0 right-0 text-center bg-black/60 text-blue-300 py-1.5 text-sm rounded-b-lg">
                Vedani-Crypter - Main Interface
              </div>
            </div>
            
            <div className="relative max-w-sm w-full border border-gray-700 rounded-lg hover:translate-y-[-3px] transition-all duration-300 hover:shadow-lg hover:shadow-blue-500/10">
              <img 
                src="https://i.ibb.co/HDTpGjZ4/433060068-33a9d53e-05eb-46f0-8870-826cf9e0643d.png" 
                alt="VBS Binder Interface" 
                className="w-full rounded-lg"
              />
              <div className="absolute bottom-2 left-0 right-0 text-center bg-black/60 text-blue-300 py-1.5 text-sm rounded-b-lg">
                VBS Binder - Generator Interface
              </div>
            </div>
          </div>

          <div className="text-center mb-5">
            <a 
              href="https://github.com/ardentus/Vedani-Crypter.git" 
              target="_blank" 
              rel="noopener noreferrer"
              className="inline-block mx-3 my-4 px-8 py-4 bg-green-600 text-white text-xl font-bold rounded-lg hover:bg-green-500 transition-all duration-300 hover:translate-y-[-2px] hover:shadow-xl hover:shadow-green-500/30 animate-pulse"
            >
              🎁 DOWNLOAD FREE CRYPTER + BONUS TOOLS 🎁
            </a>
          </div>

          <div className="bg-gradient-to-r from-green-900/50 to-blue-900/50 p-4 rounded-lg mb-5">
            <h3 className="text-xl font-bold text-green-400 mb-2 text-center">🎉 LIMITED TIME BONUS PACKAGE 🎉</h3>
            <ul className="list-none px-5 space-y-1 text-center">
              <li className="text-green-300">✨ FREE Vedani-Crypter (Worth $200)</li>
              <li className="text-green-300">✨ FREE VBS Binder Generator</li>
              <li className="text-green-300">✨ FREE LNK Exploit Builder</li>
              <li className="text-green-300">✨ FREE 888 RAT (Multi-Platform)</li>
              <li className="text-green-300">✨ Lifetime Updates Included</li>
            </ul>
          </div>

          <ul className="list-none px-5 space-y-2">
            {[
              "Runtime & Scantime crypter for EXE protection",
              "Updating stub for continuous effectiveness", 
              "Lifetime license, completely free",
              "Includes video tutorial for setup",
              "Random obfuscation for every generated file",
              "No SmartScreen or Windows Defender alerts",
              "Bind multiple files with ease",
              "Advanced anti-analysis protection",
              "Cross-platform RAT included (Windows/Android/Linux)",
              "Regular updates and new features"
            ].map((feature, index) => (
              <li key={index} className="text-blue-300 relative pl-6 hover:text-blue-400 transition-colors duration-300">
                <span className="absolute left-0 text-blue-400 text-lg">✔️</span>
                {feature}
              </li>
            ))}
          </ul>
        </section>

        <div className="text-center mt-8">
          <div className="bg-gray-800 border-2 border-blue-400 max-w-4xl mx-auto rounded-lg p-6">
            <h3 className="text-2xl md:text-3xl text-blue-400 font-bold mb-4">Educational Purpose</h3>
            <p className="text-lg text-gray-300 leading-relaxed">
              This platform is designed for cybersecurity education and research purposes. 
              All tools and demonstrations are intended to help security professionals understand 
              and defend against potential threats in controlled environments.
            </p>
          </div>
        </div>
      </div>

      {/* Fixed disclaimer */}
      <div className="fixed bottom-0 w-full bg-gray-900 py-3 text-center border-t border-red-500 text-sm text-red-400 z-50">
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
