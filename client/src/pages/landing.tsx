
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Zap, Code, Eye, Users, Activity } from "lucide-react";
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
      <div className="container mx-auto px-6 py-20">
        <div className="text-center mb-24">
          <div className="flex items-center justify-center gap-3 mb-8">
            <Shield className="w-12 h-12 text-matrix" />
            <h1 className="text-6xl md:text-8xl font-bold bg-gradient-to-r from-matrix to-green-400 bg-clip-text text-transparent">
              Millennium RAT
            </h1>
          </div>

          <p className="text-2xl text-gray-300 mb-12 max-w-4xl mx-auto leading-relaxed">
            Elite Remote Administration Tools for Cybersecurity Professionals
          </p>

          <div className="flex items-center justify-center gap-6 mb-12">
            <Badge variant="secondary" className="bg-red-900 text-red-300 text-lg px-6 py-3">
              <Activity className="w-5 h-5 mr-2" />
              {visitorCount} Active Users
            </Badge>
            <Badge variant="secondary" className="bg-green-900 text-green-300 text-lg px-6 py-3">
              <Users className="w-5 h-5 mr-2" />
              Educational Platform
            </Badge>
          </div>

          <div className="flex flex-col sm:flex-row gap-6 justify-center">
            <Button
              size="lg"
              className="bg-matrix hover:bg-green-400 text-black px-10 py-4 text-lg font-semibold transition-all duration-300 hover:scale-105 shadow-lg"
            >
              <Code className="w-6 h-6 mr-3" />
              Explore Tools
            </Button>
            <Button
              variant="outline"
              size="lg"
              className="border-matrix text-matrix hover:bg-matrix hover:text-black px-10 py-4 text-lg font-semibold"
              onClick={() => setShowAdminLogin(true)}
            >
              <Eye className="w-6 h-6 mr-3" />
              Admin Portal
            </Button>
          </div>
        </div>

        {/* Features Grid */}
        <div className="grid lg:grid-cols-3 gap-12 mb-20">
          <Card className="bg-gray-900 border-matrix border-2 hover:border-green-400 transition-all duration-300 transform hover:scale-105">
            <CardHeader className="pb-4">
              <CardTitle className="flex items-center gap-3 text-matrix text-2xl">
                <Zap className="w-8 h-8" />
                DotStealer Pro
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3 text-base">
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Fully rewritten in C++ for speed and stealth</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Small native executable, zero dependencies</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>No Microsoft Visual C++ required</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Works on Windows 7+ (32/64-bit)</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Auto StartUp for persistent access</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Anti double-launch protection</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>AutoStealer for data collection</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Keylogger for input monitoring</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Anti-VM and Anti-Debug features</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-matrix border-2 hover:border-green-400 transition-all duration-300 transform hover:scale-105">
            <CardHeader className="pb-4">
              <CardTitle className="flex items-center gap-3 text-matrix text-2xl">
                <Code className="w-8 h-8" />
                RAT Builder
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3 text-base">
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Random obfuscation for every generated file</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>No SmartScreen alerts for files</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>No Windows Defender alerts</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Privilege elevation capabilities</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Custom message boxes and UI control</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>One-command desktop file access</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>File encryption/decryption tools</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Window management controls</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>System information gathering</li>
              </ul>
            </CardContent>
          </Card>

          <Card className="bg-gray-900 border-matrix border-2 hover:border-green-400 transition-all duration-300 transform hover:scale-105">
            <CardHeader className="pb-4">
              <CardTitle className="flex items-center gap-3 text-matrix text-2xl">
                <Shield className="w-8 h-8" />
                Advanced Features
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-3 text-base">
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>User session management</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Remote input simulation</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Command line execution</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Self-uninstall capability</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>File system operations</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>System control functions</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Process management tools</li>
                <li className="flex items-start"><span className="text-matrix mr-3 text-lg">✔️</span>Educational demonstrations</li>
              </ul>
            </CardContent>
          </Card>
        </div>

        {/* Educational Notice */}
        <div className="text-center">
          <Card className="bg-gray-900 border-matrix border-2 max-w-4xl mx-auto">
            <CardHeader>
              <CardTitle className="text-3xl text-matrix">Educational Purpose</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-lg text-gray-300 leading-relaxed">
                This platform is designed for cybersecurity education and research purposes. 
                All tools and demonstrations are intended to help security professionals understand 
                and defend against potential threats in controlled environments.
              </p>
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
