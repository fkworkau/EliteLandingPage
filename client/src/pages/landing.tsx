import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Zap, Code, Eye, Download, Star, Users, Activity } from "lucide-react";
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
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-800">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="text-center mb-16">
          <div className="flex items-center justify-center gap-2 mb-6">
            <Shield className="w-8 h-8 text-matrix" />
            <h1 className="text-4xl md:text-6xl font-bold bg-gradient-to-r from-matrix to-green-400 bg-clip-text text-transparent">
              Millennium RAT
            </h1>
          </div>

          <p className="text-xl text-gray-300 mb-8 max-w-3xl mx-auto">
            Elite Remote Administration Tools for Cybersecurity Professionals
          </p>

          <div className="flex items-center justify-center gap-4 mb-8">
            <Badge variant="secondary" className="bg-red-900 text-red-300">
              <Activity className="w-4 h-4 mr-1" />
              {visitorCount} Active Users
            </Badge>
            <Badge variant="secondary" className="bg-green-900 text-green-300">
              <Star className="w-4 h-4 mr-1" />
              Premium Quality
            </Badge>
          </div>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <a
              href="#pricing"
              className="bg-red-700 hover:bg-red-600 text-white px-8 py-3 rounded-lg font-mono transition-all duration-300 hover:scale-105 shadow-lg"
            >
              <Download className="w-5 h-5 inline mr-2" />
              Buy Now
            </a>
            <Button
              variant="outline"
              className="border-matrix text-matrix hover:bg-matrix hover:text-black"
              onClick={() => setShowAdminLogin(true)}
            >
              <Eye className="w-5 h-5 mr-2" />
              Admin Portal
            </Button>
          </div>
        </div>

        {/* Features Grid */}
        <div className="grid md:grid-cols-3 gap-8 mb-16">
          <Card className="bg-gray-900 border-matrix">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-matrix">
                <Zap className="w-5 h-5" />
                DotStealer Pro
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Fully rewritten in C++ for speed and stealth</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Small native executable, zero dependencies</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>No Microsoft Visual C++ required</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Works on Windows 7+ (32/64-bit)</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Auto StartUp for persistent access</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Anti double-launch protection</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>AutoStealer for effortless data theft</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Keylogger for capturing every keystroke</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Anti-VM and Anti-Debug for ultimate evasion</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-matrix">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-matrix">
                <Code className="w-5 h-5" />
                RAT Builder
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Random obfuscation for every generated file</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>No SmartScreen alerts for binder or downloaded files</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>No Windows Defender alerts</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Privilege elevation for deeper control</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Messageboxes, wallpaper changes, display rotation</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>One-command desktop file grabbing</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>File encryption/decryption</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Window minimize/maximize control</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Get active window title, battery info, software list</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-matrix">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-matrix">
                <Shield className="w-5 h-5" />
                Advanced Features
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm">
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>User logoff, PC hibernation, BSOD trigger</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>SendKeyPress for remote input</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>CMD command execution</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Self-uninstall capability</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>File/Folder ops (copy, delete, download, upload, list)</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>System shutdown, restart, logoff</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Process manager (run, list, kill, get path)</li>
                <li className="flex items-start"><span className="text-matrix mr-2">✔️</span>Bot gifting and much more</li>
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* Pricing Section */}
        <div id="pricing" className="text-center">
          <h2 className="text-3xl font-bold text-matrix mb-8">Get Premium Access</h2>
          <Card className="bg-gray-900 border-matrix max-w-md mx-auto">
            <CardHeader>
              <CardTitle className="text-2xl text-matrix">Millennium RAT Suite</CardTitle>
              <div className="text-4xl font-bold text-white">
                $199<span className="text-lg text-gray-400">/lifetime</span>
              </div>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm mb-6">
                <li className="flex items-center"><span className="text-matrix mr-2">✔️</span>Complete RAT Suite</li>
                <li className="flex items-center"><span className="text-matrix mr-2">✔️</span>Lifetime Updates</li>
                <li className="flex items-center"><span className="text-matrix mr-2">✔️</span>24/7 Support</li>
                <li className="flex items-center"><span className="text-matrix mr-2">✔️</span>Educational License</li>
              </ul>
              <Button className="w-full bg-red-700 hover:bg-red-600 text-white">
                Purchase Now
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      <CookieBanner />
      <AdminLoginModal 
        isOpen={showAdminLogin} 
        onClose={() => setShowAdminLogin(false)} 
      />
    </div>
  );
}