import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import CookieBanner from "@/components/cookie-banner";
import AdminLoginModal from "@/components/admin-login-modal";
import { Terminal, Bug, VenetianMask, Shield, ChevronDown, ExternalLink } from "lucide-react";

export default function Landing() {
  const [, setLocation] = useLocation();
  const [showAdminModal, setShowAdminModal] = useState(false);
  const [expandedFeatures, setExpandedFeatures] = useState<string | null>(null);

  const toggleFeatures = (toolName: string) => {
    setExpandedFeatures(expandedFeatures === toolName ? null : toolName);
  };

  const handleAdminAccess = () => {
    setLocation("/admin-portal");
  };

  return (
    <div className="min-h-screen bg-terminal text-matrix overflow-x-hidden">
      <CookieBanner />
      
      {/* Navigation */}
      <nav className="fixed top-0 left-0 right-0 bg-panel/95 backdrop-blur-sm border-b border-matrix/20 z-40">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Terminal className="text-matrix text-xl" />
            <span className="font-mono text-lg font-bold">MILLENNIUM-RAT.NET</span>
          </div>
          <div className="hidden md:flex items-center space-x-6 font-mono text-sm">
            <a href="#tools" className="hover:text-matrix transition-colors">Tools</a>
            <a href="#features" className="hover:text-matrix transition-colors">Features</a>
            <a href="#contact" className="hover:text-matrix transition-colors">Contact</a>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => setShowAdminModal(true)}
              className="text-gray-500 hover:text-matrix"
            >
              <Shield className="w-4 h-4" />
            </Button>
          </div>
        </div>
      </nav>

      <div className="pt-20">
        {/* Hero Section */}
        <section className="relative py-20 px-6">
          <div className="max-w-6xl mx-auto text-center">
            <div className="mb-8">
              <h1 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-mono font-bold mb-4 relative text-matrix glow-pulse">
                MILLENNIUM REMOTE ADMIN TOOLS
              </h1>
              <div className="font-mono text-xl text-gray-400 typing-animation">
                Unleash Your Power with Premium Cyber Weapons
              </div>
            </div>
            
            {/* Terminal Window */}
            <div className="max-w-4xl mx-auto terminal-window overflow-hidden shadow-2xl">
              <div className="terminal-header">
                <div className="terminal-dot terminal-dot-red"></div>
                <div className="terminal-dot terminal-dot-yellow"></div>
                <div className="terminal-dot terminal-dot-green"></div>
                <span className="text-gray-400 text-sm font-mono ml-4">elite-terminal v4.0</span>
              </div>
              <div className="p-6 font-mono text-left">
                <div className="text-matrix">&gt; Welcome to the ultimate collection of hacking tools...</div>
                <div className="text-gray-400 mt-2">&gt; Crafted for the elite cybersecurity professionals</div>
                <div className="text-accent mt-2">&gt; From remote access to stealth data extraction</div>
                <div className="text-gray-400 mt-2">&gt; Tools designed to dominate any system with precision</div>
                <div className="text-matrix mt-4 matrix-pulse">&gt; System ready. Choose your weapon._</div>
              </div>
            </div>

            <div className="mt-8 flex flex-wrap justify-center gap-4">
              <Button asChild className="cyber-button">
                <a href="https://t.me/shinyenigma" target="_blank" rel="noopener noreferrer">
                  <ExternalLink className="w-4 h-4 mr-2" />
                  Contact: @shinyenigma
                </a>
              </Button>
              <Card className="bg-panel border-matrix/30">
                <CardContent className="px-6 py-3 font-mono text-sm">
                  <span className="text-warning mr-2">💰</span>
                  Payments: USDT, BTC, TRX, XMR, ETH, LTC
                </CardContent>
              </Card>
            </div>
          </div>
        </section>

        {/* Tools Section */}
        <section id="tools" className="py-16 px-6">
          <div className="max-w-6xl mx-auto">
            
            {/* Millennium RAT */}
            <Card className="mb-16 bg-panel border-matrix/20 hover:border-matrix/40 transition-all duration-300">
              <CardContent className="p-8">
                <div className="grid md:grid-cols-2 gap-8 items-center">
                  <div>
                    <h2 className="text-3xl font-mono font-bold text-matrix mb-4 flex items-center">
                      <Bug className="mr-3" />
                      Millennium RAT v4.0
                    </h2>
                    <p className="text-gray-300 mb-6 leading-relaxed">
                      A battle-tested Remote Access Tool with a 2-year legacy, now fully rewritten in C++ for unmatched performance. Control via Telegram with no server or port forwarding needed. Steal data, log keys, and own systems effortlessly.
                    </p>
                    
                    {/* Feature Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mb-6">
                      {[
                        "C++ Rewritten for Speed",
                        "Zero Dependencies", 
                        "Windows 7+ Compatible",
                        "Auto StartUp Persistence",
                        "Anti-VM & Anti-Debug",
                        "Keylogger & AutoStealer"
                      ].map((feature) => (
                        <div key={feature} className="flex items-center text-sm text-gray-400">
                          <span className="text-matrix mr-2">✓</span>
                          {feature}
                        </div>
                      ))}
                    </div>
                    
                    <Button asChild className="cyber-button-accent">
                      <a href="https://t.me/shinyenigma" target="_blank" rel="noopener noreferrer">
                        🛒 Buy Now
                      </a>
                    </Button>
                  </div>
                  
                  <div className="relative">
                    <Card className="bg-terminal border-matrix/30 h-64 flex items-center justify-center">
                      <div className="text-center">
                        <Terminal className="w-16 h-16 text-matrix mb-4 mx-auto" />
                        <div className="font-mono text-matrix">Millennium RAT</div>
                        <div className="font-mono text-sm text-gray-400">Control Panel Interface</div>
                      </div>
                    </Card>
                  </div>
                </div>
                
                {/* Expandable Features */}
                <div className="mt-8 border-t border-matrix/20 pt-6">
                  <Button
                    variant="ghost"
                    onClick={() => toggleFeatures('millennium')}
                    className="flex items-center text-matrix font-mono text-sm hover:text-matrix/80"
                  >
                    <ChevronDown 
                      className={`mr-2 transition-transform ${expandedFeatures === 'millennium' ? 'rotate-180' : ''}`} 
                    />
                    View Full Feature List (60+ Features)
                  </Button>
                  {expandedFeatures === 'millennium' && (
                    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 text-sm text-gray-400">
                      {[
                        "Remote PowerShell/CMD execution",
                        "System info grabbing (CPU, GPU, RAM)",
                        "Discord token theft",
                        "Telegram data extraction",
                        "Browser data theft",
                        "Crypto wallet recovery",
                        "Webcamera capture",
                        "Privilege elevation",
                        "File encryption/decryption",
                        "Process manager",
                        "System shutdown controls",
                        "Self-uninstall capability"
                      ].map((feature) => (
                        <div key={feature}>• {feature}</div>
                      ))}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* DotStealer */}
            <Card className="mb-16 bg-panel border-matrix/20 hover:border-matrix/40 transition-all duration-300">
              <CardContent className="p-8">
                <div className="grid md:grid-cols-2 gap-8 items-center">
                  <div className="order-2 md:order-1 relative">
                    <Card className="bg-terminal border-matrix/30 h-64 flex items-center justify-center">
                      <div className="text-center">
                        <VenetianMask className="w-16 h-16 text-matrix mb-4 mx-auto" />
                        <div className="font-mono text-matrix">DotStealer</div>
                        <div className="font-mono text-sm text-gray-400">Configuration Panel</div>
                      </div>
                    </Card>
                  </div>
                  
                  <div className="order-1 md:order-2">
                    <h2 className="text-3xl font-mono font-bold text-matrix mb-4 flex items-center">
                      <VenetianMask className="mr-3" />
                      DotStealer
                    </h2>
                    <p className="text-gray-300 mb-6 leading-relaxed">
                      A multifunctional Windows stealer that sends logs via Telegram bot—no dedicated server needed. Lifetime license for only $30 (updates included). Stay updated via my Telegram channel.
                    </p>
                    
                    {/* Price Tag */}
                    <Card className="bg-matrix/10 border-matrix/30 p-4 mb-6">
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-matrix font-mono font-bold text-2xl">$30</div>
                          <div className="text-gray-400 text-sm">Lifetime License</div>
                        </div>
                        <div className="text-right">
                          <div className="text-matrix text-sm font-mono">✓ Free Updates</div>
                          <div className="text-gray-400 text-sm">✓ Telegram Support</div>
                        </div>
                      </div>
                    </Card>
                    
                    <Button asChild className="cyber-button-accent">
                      <a href="https://t.me/shinyenigma" target="_blank" rel="noopener noreferrer">
                        🛒 Buy Now - $30
                      </a>
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Vedani-Crypter */}
            <Card className="mb-16 bg-panel border-matrix/20 hover:border-matrix/40 transition-all duration-300">
              <CardContent className="p-8">
                <div className="grid md:grid-cols-2 gap-8 items-center">
                  <div>
                    <div className="flex items-center mb-4">
                      <h2 className="text-3xl font-mono font-bold text-matrix flex items-center">
                        <Shield className="mr-3" />
                        Vedani-Crypter
                      </h2>
                      <Badge className="bg-matrix text-terminal text-xs px-2 py-1 ml-3 font-bold">
                        FREE
                      </Badge>
                    </div>
                    <p className="text-gray-300 mb-6 leading-relaxed">
                      A renowned private Runtime & Scantime crypter with an updating stub and lifetime license—available for free. Protect your EXE files from antivirus scans with this powerful tool, complete with a video tutorial.
                    </p>
                    
                    <Card className="bg-matrix/10 border-matrix/30 p-4 mb-6">
                      <div className="font-mono text-matrix text-lg font-bold mb-2">FREE DOWNLOAD</div>
                      <div className="text-gray-400 text-sm">✓ Lifetime License</div>
                      <div className="text-gray-400 text-sm">✓ Video Tutorial Included</div>
                      <div className="text-gray-400 text-sm">✓ Regular Stub Updates</div>
                    </Card>
                    
                    <Button asChild className="cyber-button">
                      <a href="https://t.me/shinyenigma" target="_blank" rel="noopener noreferrer">
                        📥 Download Free
                      </a>
                    </Button>
                  </div>
                  
                  <div className="relative">
                    <Card className="bg-terminal border-matrix/30 h-64 flex items-center justify-center">
                      <div className="text-center">
                        <Shield className="w-16 h-16 text-matrix mb-4 mx-auto" />
                        <div className="font-mono text-matrix">Vedani-Crypter</div>
                        <div className="font-mono text-sm text-gray-400">Main Interface</div>
                      </div>
                    </Card>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </section>

        {/* Stats Section */}
        <section className="py-16 px-6 bg-panel/50">
          <div className="max-w-6xl mx-auto">
            <div className="grid grid-cols-1 md:grid-cols-4 gap-8 text-center">
              <Card className="bg-panel border-matrix/20 p-6">
                <div className="text-3xl font-mono font-bold text-matrix mb-2">1,247</div>
                <div className="text-gray-400 text-sm">Active Users</div>
              </Card>
              <Card className="bg-panel border-matrix/20 p-6">
                <div className="text-3xl font-mono font-bold text-matrix mb-2">89</div>
                <div className="text-gray-400 text-sm">Countries</div>
              </Card>
              <Card className="bg-panel border-matrix/20 p-6">
                <div className="text-3xl font-mono font-bold text-matrix mb-2">3</div>
                <div className="text-gray-400 text-sm">Elite Tools</div>
              </Card>
              <Card className="bg-panel border-matrix/20 p-6">
                <div className="text-3xl font-mono font-bold text-matrix mb-2">99.9%</div>
                <div className="text-gray-400 text-sm">Uptime</div>
              </Card>
            </div>
          </div>
        </section>

        {/* Contact Section */}
        <section id="contact" className="py-16 px-6">
          <div className="max-w-4xl mx-auto text-center">
            <h2 className="text-3xl font-mono font-bold text-matrix mb-8">Get in Touch</h2>
            <Card className="bg-panel border-matrix/20 p-8">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="text-left">
                  <h3 className="font-mono text-lg text-matrix mb-4">Contact Information</h3>
                  <div className="space-y-3">
                    <div className="flex items-center text-gray-300">
                      <span className="text-matrix mr-3">📱</span>
                      <span>@shinyenigma</span>
                    </div>
                    <div className="flex items-center text-gray-300">
                      <span className="text-matrix mr-3">🌐</span>
                      <span>Available 24/7</span>
                    </div>
                    <div className="flex items-center text-gray-300">
                      <span className="text-matrix mr-3">🗣️</span>
                      <span>English & Russian</span>
                    </div>
                  </div>
                </div>
                <div className="text-left">
                  <h3 className="font-mono text-lg text-matrix mb-4">Payment Methods</h3>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    {["USDT (TRC20)", "Bitcoin (BTC)", "Tron (TRX)", "Monero (XMR)", "Ethereum (ETH)", "Litecoin (LTC)"].map((method) => (
                      <div key={method} className="text-gray-300">• {method}</div>
                    ))}
                  </div>
                </div>
              </div>
            </Card>
          </div>
        </section>
      </div>

      {/* Footer */}
      <footer className="bg-panel border-t border-matrix/20 py-8 px-6 text-center">
        <div className="max-w-6xl mx-auto">
          <div className="text-danger text-sm mb-4 font-mono">
            ⚠️ EDUCATIONAL DISCLAIMER: These tools are for authorized security testing and educational purposes only. 
            Unauthorized access to computer systems is illegal and unethical.
          </div>
          <div className="text-gray-400 text-sm">
            © 2024 Elite Hacking Tools. For educational and authorized security testing purposes only.
          </div>
        </div>
      </footer>

      <AdminLoginModal 
        open={showAdminModal} 
        onOpenChange={setShowAdminModal}
        onSuccess={handleAdminAccess}
      />
    </div>
  );
}
