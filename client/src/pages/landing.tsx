import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Brain, 
  Code, 
  Shield, 
  Zap, 
  Upload, 
  Download, 
  MessageSquare,
  Triangle,
  Send,
  FileCode,
  Minimize,
  Lock,
  Unlock,
  Package,
  Bot,
  Eye,
  Settings,
  Terminal,
  Network,
  Key
} from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import AdminLoginModal from "@/components/admin-login-modal";
import CookieBanner from "@/components/cookie-banner";

export default function Landing() {
  const [showAdminModal, setShowAdminModal] = useState(false);
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiResponse, setAiResponse] = useState("");
  const [scriptInput, setScriptInput] = useState("");
  const [scriptOutput, setScriptOutput] = useState("");
  const [selectedTool, setSelectedTool] = useState("syntax-fixer");
  const [crypterConfig, setCrypterConfig] = useState({
    inputFile: null as File | null,
    outputName: "protected_executable",
    antiDebug: true,
    antiVM: true,
    polymorphic: true,
    dotNetSupport: true,
    compressionLevel: "high"
  });
  const fileInputRef = useRef<HTMLInputElement>(null);

  // AI Chat mutation
  const aiChat = useMutation({
    mutationFn: async (prompt: string) => {
      const response = await fetch("/api/ai-chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
      });
      if (!response.ok) throw new Error("AI request failed");
      return response.json();
    },
    onSuccess: (data) => {
      setAiResponse(data.response);
    },
  });

  // Script processor mutation
  const scriptProcessor = useMutation({
    mutationFn: async ({ script, tool }: { script: string; tool: string }) => {
      const response = await fetch("/api/script-tools", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ script, tool }),
      });
      if (!response.ok) throw new Error("Script processing failed");
      return response.json();
    },
    onSuccess: (data) => {
      setScriptOutput(data.processedScript);
    },
  });

  // Crypter processor mutation
  const crypterProcessor = useMutation({
    mutationFn: async (formData: FormData) => {
      const response = await fetch("/api/crypter", {
        method: "POST",
        body: formData,
      });
      if (!response.ok) throw new Error("Crypter processing failed");
      return response.json();
    },
  });

  const handleAiSubmit = () => {
    if (!aiPrompt.trim()) return;
    aiChat.mutate(aiPrompt);
  };

  const handleCrypterSubmit = () => {
    if (!crypterConfig.inputFile) return;

    const formData = new FormData();
    formData.append('file', crypterConfig.inputFile);
    formData.append('config', JSON.stringify(crypterConfig));

    crypterProcessor.mutate(formData);
  };

  const scriptTools = [
    { id: "syntax-fixer", label: "Syntax Fixer", icon: Code, description: "Automatically fix syntax errors in your scripts" },
    { id: "minifier", label: "Script Minifier", icon: Minimize, description: "Compress and optimize your code" },
    { id: "obfuscator", label: "Code Obfuscator", icon: Lock, description: "Protect your scripts from reverse engineering" },
    { id: "deobfuscator", label: "Code Deobfuscator", icon: Unlock, description: "Deobfuscate and analyze protected code" }
  ];

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-blue-900 text-white">
      {/* Header with Logo - Mobile Optimized */}
      <header className="relative py-4 sm:py-8 px-4 sm:px-6 text-center">
        <div className="flex flex-col sm:flex-row items-center justify-center mb-4">
          <Triangle className="w-8 sm:w-12 h-8 sm:h-12 text-cyan-400 mb-2 sm:mb-0 sm:mr-4" style={{ filter: 'drop-shadow(0 0 10px #00bcd4)' }} />
          <h1 className="text-3xl sm:text-4xl lg:text-6xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
            MILLENNIUM
          </h1>
        </div>
        <p className="text-sm sm:text-xl text-gray-300 mb-4 sm:mb-8">Advanced Cybersecurity Framework</p>
      </header>

      <div className="container mx-auto px-4 sm:px-6 space-y-8 sm:space-y-12">
        {/* Millennium AI Section - Enhanced */}
        <section className="text-center mb-16">
          <div className="relative bg-gradient-to-r from-gray-900/80 to-gray-800/80 rounded-3xl p-8 sm:p-12 border border-cyan-500/30 backdrop-blur">
            <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/10 to-blue-500/10 rounded-3xl"></div>
            <div className="relative z-10">
              <div className="flex items-center justify-center mb-8">
                <Brain className="w-12 sm:w-16 h-12 sm:h-16 text-cyan-400 mr-4" style={{ filter: 'drop-shadow(0 0 20px #00bcd4)' }} />
                <h2 className="text-4xl sm:text-6xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                  Millennium AI
                </h2>
              </div>
              <p className="text-lg sm:text-2xl text-gray-300 mb-8 max-w-4xl mx-auto">
                Advanced AI-powered cybersecurity assistant for script generation, payload optimization, and threat analysis
              </p>

              <Card className="max-w-4xl mx-auto bg-black/40 border-cyan-500/50 backdrop-blur">
                <CardContent className="p-6">
                  <div className="space-y-4">
                    <Textarea
                      placeholder="Ask Millennium AI to write scripts, analyze code, or answer cybersecurity questions..."
                      value={aiPrompt}
                      onChange={(e) => setAiPrompt(e.target.value)}
                      className="bg-gray-800/50 border-gray-600 text-white min-h-[100px]"
                    />
                    <Button
                      onClick={handleAiSubmit}
                      disabled={aiChat.isPending || !aiPrompt.trim()}
                      className="w-full bg-cyan-600 hover:bg-cyan-700"
                    >
                      <Brain className="w-4 h-4 mr-2" />
                      {aiChat.isPending ? 'Processing...' : 'Ask Millennium AI'}
                    </Button>
                    {aiResponse && (
                      <div className="mt-6 p-4 bg-gray-800/50 rounded-lg border border-cyan-500/30">
                        <h4 className="text-cyan-400 font-semibold mb-2">AI Response:</h4>
                        <pre className="text-gray-300 whitespace-pre-wrap text-sm">{aiResponse}</pre>
                      </div>
                    )}
                  </div>
                </CardContent>
              </Card>
            </div>
          </div>
        </section>

        {/* RAT & Stealer Showcase */}
        <section className="mb-16">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Millennium RAT */}
            <div className="bg-gradient-to-br from-green-900/20 to-gray-900/80 rounded-2xl p-6 border border-green-500/30">
              <div className="text-center mb-6">
                <Bot className="w-12 h-12 text-green-400 mx-auto mb-4" />
                <h3 className="text-2xl font-bold text-green-400 mb-2">Millennium RAT</h3>
                <p className="text-gray-300">Advanced Remote Access Tool with stealth capabilities</p>
              </div>
              <div className="bg-black/40 rounded-lg p-4 mb-4">
                <img 
                  src="https://i.imgur.com/g6sSZy3.jpeg" 
                  alt="Millennium RAT Interface" 
                  className="w-full h-48 object-cover rounded"
                />
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex items-center text-green-400">
                  <Zap className="w-4 h-4 mr-2" />
                  Real-time remote control
                </div>
                <div className="flex items-center text-green-400">
                  <Eye className="w-4 h-4 mr-2" />
                  Advanced persistence mechanisms
                </div>
                <div className="flex items-center text-green-400">
                  <Shield className="w-4 h-4 mr-2" />
                  Anti-detection features
                </div>
              </div>
              <div className="mt-4">
                <a 
                  href="https://t.me/milleniumrat" 
                  target="_blank" 
                  rel="noopener noreferrer"
                  className="inline-flex items-center justify-center w-full px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg transition-colors font-medium"
                >
                  <Bot className="w-4 h-4 mr-2" />
                  Buy Millennium RAT
                </a>
              </div>
            </div>

            {/* Dot Stealer */}
            <div className="bg-gradient-to-br from-red-900/20 to-gray-900/80 rounded-2xl p-6 border border-red-500/30">
              <div className="text-center mb-6">
                <Key className="w-12 h-12 text-red-400 mx-auto mb-4" />
                <h3 className="text-2xl font-bold text-red-400 mb-2">Dot Stealer</h3>
                <p className="text-gray-300">Professional data extraction and credential harvesting</p>
              </div>
              <div className="bg-black/40 rounded-lg p-4 mb-4">
                <img 
                  src="https://i.imgur.com/zJmEvwQ.jpeg" 
                  alt="Dot Stealer Interface" 
                  className="w-full h-48 object-cover rounded"
                />
              </div>
              <div className="space-y-2 text-sm">
                <div className="flex items-center text-red-400">
                  <Download className="w-4 h-4 mr-2" />
                  Browser credential extraction
                </div>
                <div className="flex items-center text-red-400">
                  <Network className="w-4 h-4 mr-2" />
                  Cryptocurrency wallet detection
                </div>
                <div className="flex items-center text-red-400">
                  <MessageSquare className="w-4 h-4 mr-2" />
                  Discord/Telegram token harvesting
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Script Tools Section */}
        <section className="mb-16">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-white mb-4">Script Processing Tools</h2>
            <p className="text-gray-300">Professional code optimization and obfuscation utilities</p>
          </div>

          <Card className="bg-gray-900/50 border-gray-700">
            <CardContent className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                {scriptTools.map((tool) => (
                  <Button
                    key={tool.id}
                    variant={selectedTool === tool.id ? "default" : "outline"}
                    onClick={() => setSelectedTool(tool.id)}
                    className={`h-auto p-4 flex flex-col items-center space-y-2 ${
                      selectedTool === tool.id ? 'bg-cyan-600 border-cyan-500' : 'border-gray-600'
                    }`}
                  >
                    <tool.icon className="w-6 h-6" />
                    <span className="text-xs text-center">{tool.label}</span>
                  </Button>
                ))}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium mb-2">Input Script</label>
                  <Textarea
                    placeholder="Paste your script here for processing..."
                    value={scriptInput}
                    onChange={(e) => setScriptInput(e.target.value)}
                    className="bg-gray-800 border-gray-600 text-white h-64 font-mono text-sm"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Processed Output</label>
                  <Textarea
                    value={scriptOutput}
                    readOnly
                    className="bg-gray-800 border-gray-600 text-white h-64 font-mono text-sm"
                    placeholder="Processed script will appear here..."
                  />
                </div>
              </div>

              <div className="flex gap-4 mt-6">
                <Button
                  onClick={() => scriptProcessor.mutate({ script: scriptInput, tool: selectedTool })}
                  disabled={scriptProcessor.isPending || !scriptInput.trim()}
                  className="bg-cyan-600 hover:bg-cyan-700 flex-1"
                >
                  <Code className="w-4 h-4 mr-2" />
                  {scriptProcessor.isPending ? 'Processing...' : `Apply ${scriptTools.find(t => t.id === selectedTool)?.label}`}
                </Button>

                <Button 
                  variant="outline" 
                  className="border-gray-600"
                  onClick={() => {
                    setScriptInput("");
                    setScriptOutput("");
                  }}
                >
                  Clear
                </Button>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Advanced Polymorphic Crypter */}
        <section className="mb-16">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-white mb-4">Advanced Polymorphic Crypter</h2>
            <p className="text-gray-300">Professional executable protection and obfuscation</p>
          </div>

          <Card className="bg-gray-900/50 border-gray-700">
            <CardContent className="p-6">
              <div className="space-y-6">
                <div>
                  <label className="block text-sm font-medium mb-2">Upload Executable</label>
                  <div className="border-2 border-dashed border-gray-600 rounded-lg p-6 text-center">
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept=".exe,.dll,.bin"
                      onChange={(e) => setCrypterConfig({...crypterConfig, inputFile: e.target.files?.[0] || null})}
                      className="hidden"
                    />
                    <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                    <p className="text-gray-300 mb-2">
                      {crypterConfig.inputFile ? crypterConfig.inputFile.name : "Drop your executable here or click to browse"}
                    </p>
                    <Button 
                      variant="outline" 
                      onClick={() => fileInputRef.current?.click()}
                      className="border-gray-600"
                    >
                      Choose File
                    </Button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div>
                    <label className="block text-sm font-medium mb-2">Output Name</label>
                    <Input
                      value={crypterConfig.outputName}
                      onChange={(e) => setCrypterConfig(prev => ({ ...prev, outputName: e.target.value }))}
                      className="bg-gray-800 border-gray-600 text-white"
                      placeholder="protected_executable"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-2">Compression Level</label>
                    <Select 
                      value={crypterConfig.compressionLevel} 
                      onValueChange={(value) => setCrypterConfig(prev => ({ ...prev, compressionLevel: value }))}
                    >
                      <SelectTrigger className="bg-gray-800 border-gray-600 text-white">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="low">Low</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="high">High</SelectItem>
                        <SelectItem value="maximum">Maximum</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="flex items-center justify-between">
                    <label className="text-sm">Anti-Debug Protection</label>
                    <input 
                      type="checkbox" 
                      checked={crypterConfig.antiDebug}
                      onChange={(e) => setCrypterConfig(prev => ({ ...prev, antiDebug: e.target.checked }))}
                      className="rounded"
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <label className="text-sm">Anti-VM Detection</label>
                    <input 
                      type="checkbox" 
                      checked={crypterConfig.antiVM}
                      onChange={(e) => setCrypterConfig(prev => ({ ...prev, antiVM: e.target.checked }))}
                      className="rounded"
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <label className="text-sm">Polymorphic Engine</label>
                    <input 
                      type="checkbox" 
                      checked={crypterConfig.polymorphic}
                      onChange={(e) => setCrypterConfig(prev => ({ ...prev, polymorphic: e.target.checked }))}
                      className="rounded"
                    />
                  </div>
                  <div className="flex items-center justify-between">
                    <label className="text-sm">.NET Support</label>
                    <input 
                      type="checkbox" 
                      checked={crypterConfig.dotNetSupport}
                      onChange={(e) => setCrypterConfig(prev => ({ ...prev, dotNetSupport: e.target.checked }))}
                      className="rounded"
                    />
                  </div>
                </div>

                <Button
                  onClick={handleCrypterSubmit}
                  disabled={crypterProcessor.isPending || !crypterConfig.inputFile}
                  className="w-full bg-red-600 hover:bg-red-700"
                >
                  <Package className="w-4 h-4 mr-2" />
                  {crypterProcessor.isPending ? 'Encrypting...' : 'Generate Protected Executable'}
                </Button>

                <Alert className="border-yellow-500/30 bg-yellow-500/10">
                  <AlertDescription className="text-yellow-200">
                    <strong>Security Notice:</strong> This crypter generates FUD (Fully Undetectable) executables. 
                    Use only for authorized penetration testing and security research.
                  </AlertDescription>
                </Alert>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Footer */}
        <footer className="text-center py-8 border-t border-gray-700">
          <div className="flex items-center justify-center space-x-6 mb-4">
            <Button variant="outline" className="border-cyan-500 text-cyan-400">
              <Send className="w-4 h-4 mr-2" />
              Join Telegram
            </Button>
            <Badge variant="outline" className="border-cyan-500 text-cyan-400">
              Educational Use Only
            </Badge>
          </div>
          <p className="text-gray-400 text-sm">
            © 2024 Millennium Framework. Advanced cybersecurity training platform.
          </p>
        </footer>
      </div>

      {/* Admin Access Shield - Hidden in bottom right */}
      <div 
        className="fixed bottom-6 right-6 p-3 bg-gray-800/80 rounded-full cursor-pointer hover:bg-gray-700/80 transition-colors backdrop-blur border border-gray-600/30"
        onClick={() => setShowAdminModal(true)}
        title="Admin Access"
      >
        <Shield className="w-8 h-8 text-gray-500 hover:text-cyan-400 transition-colors duration-300" />
      </div>

      {/* Admin Login Modal */}
      <AdminLoginModal 
        isOpen={showAdminModal} 
        onClose={() => setShowAdminModal(false)} 
      />
      <CookieBanner />
    </div>
  );
}