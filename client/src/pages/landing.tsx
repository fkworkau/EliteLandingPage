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
  Terminal
} from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import AdminLoginModal from "@/components/admin-login-modal";
import CookieBanner from "@/components/cookie-banner";
import { Network, Key } from "lucide-react";

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

  // Millennium AI Chat
  const aiChat = useMutation({
    mutationFn: async (prompt: string) => {
      const response = await fetch('/api/millennium-ai', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt })
      });
      if (!response.ok) throw new Error('AI request failed');
      return response.json();
    },
    onSuccess: (data) => {
      setAiResponse(data.response);
    }
  });

  // Script Processing Tools
  const scriptProcessor = useMutation({
    mutationFn: async ({ script, tool }: { script: string; tool: string }) => {
      const response = await fetch('/api/script-tools', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script, tool })
      });
      if (!response.ok) throw new Error('Script processing failed');
      return response.json();
    },
    onSuccess: (data) => {
      setScriptOutput(data.processedScript);
      // Store metadata for display
    }
  });

  // Advanced Crypter
  const [compileStep, setCompileStep] = useState<'encrypt' | 'compile'>('encrypt');
  const [cryptedFilename, setCryptedFilename] = useState('');

  const crypterProcessor = useMutation({
    mutationFn: async (formData: FormData) => {
      const response = await fetch('/api/advanced-crypter', {
        method: 'POST',
        body: formData
      });
      if (!response.ok) throw new Error('Crypter processing failed');
      return response.json();
    },
    onSuccess: (data) => {
      setCryptedFilename(data.filename);
      setCompileStep('compile');
    }
  });

  // Executable Compiler
  const executableCompiler = useMutation({
    mutationFn: async (data: { filename: string; compileOptions: any }) => {
      const response = await fetch('/api/compile-executable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
      });
      if (!response.ok) throw new Error('Compilation failed');
      return response.json();
    },
    onSuccess: (data) => {
      // Trigger download of compiled executable
      const link = document.createElement('a');
      link.href = data.downloadUrl;
      link.download = data.filename;
      link.click();
      setCompileStep('encrypt');
      setCryptedFilename('');
    }
  });

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setCrypterConfig(prev => ({ ...prev, inputFile: file }));
    }
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
      {/* Header with Logo */}
      <header className="relative py-8 px-6 text-center">
        <div className="flex items-center justify-center mb-4">
          <Triangle className="w-12 h-12 text-cyan-400 mr-4" style={{ filter: 'drop-shadow(0 0 10px #00bcd4)' }} />
          <h1 className="text-6xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
            MILLENNIUM
          </h1>
        </div>
        <p className="text-xl text-gray-300 mb-8">Advanced Cybersecurity Framework</p>


      </header>

      {/* Hero Section */}
      <section className="relative py-20 bg-gradient-to-br from-black via-gray-900 to-blue-900 text-white overflow-hidden">
        <div className="absolute inset-0 opacity-30" style={{
          backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.05'%3E%3Cpath d='M36 34v-4h-2v4h-4v2h4v4h2v-4h4v-2h-4zm0-30V0h-2v4h-4v2h4v4h2V6h4V4h-4zM6 34v-4H4v4H0v2h4v4h2v-4h4v-2H6zM6 4V0H4v4H0v2h4v4h2V6h4V4H6z'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`
        }}></div>

        {/* Screenshots Grid */}
        <div className="container mx-auto px-4 mb-16">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
            <div className="bg-gray-800/50 rounded-lg p-4 border border-cyan-500/30">
                <img 
                  src="/attached_assets/screenshot-1748942482391.png" 
                  alt="Admin Dashboard Interface" 
                  className="w-full h-32 object-cover rounded mb-3"
                />
                <h3 className="text-cyan-400 font-semibold text-sm">Admin Control Panel</h3>
                <p className="text-gray-300 text-xs">Comprehensive monitoring dashboard</p>
              </div>

              <div className="bg-gray-800/50 rounded-lg p-4 border border-green-500/30">
                <img 
                  src="/attached_assets/screenshot-1748942488659.png" 
                  alt="RAT Builder Interface" 
                  className="w-full h-32 object-cover rounded mb-3"
                />
                <h3 className="text-green-400 font-semibold text-sm">RAT Builder</h3>
                <p className="text-gray-300 text-xs">Advanced payload generation</p>
              </div>

              <div className="bg-gray-800/50 rounded-lg p-4 border border-yellow-500/30">
                <img 
                  src="/attached_assets/screenshot-1748942540883.png" 
                  alt="Network Sniffer" 
                  className="w-full h-32 object-cover rounded mb-3"
                />
                <h3 className="text-yellow-400 font-semibold text-sm">Network Analysis</h3>
                <p className="text-gray-300 text-xs">Real-time traffic monitoring</p>
              </div>

              <div className="bg-gray-800/50 rounded-lg p-4 border border-red-500/30">
                <img 
                  src="/attached_assets/screenshot-1748942549503.png" 
                  alt="Executable Builder" 
                  className="w-full h-32 object-cover rounded mb-3"
                />
                <h3 className="text-red-400 font-semibold text-sm">Tool Compilation</h3>
                <p className="text-gray-300 text-xs">Portable executable creation</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <div className="container mx-auto px-6 space-y-12">
        {/* Millennium AI Section */}
        <section className="text-center mb-16">
          <div className="flex items-center justify-center mb-6">
            <Brain className="w-8 h-8 text-cyan-400 mr-3" />
            <h2 className="text-4xl font-bold text-cyan-400">Millennium AI</h2>
          </div>
          <p className="text-lg text-gray-300 mb-8">AI-powered cybersecurity assistant for script generation and security analysis</p>

          <Card className="max-w-4xl mx-auto bg-gray-900/50 border-cyan-500/30 backdrop-blur">
            <CardContent className="p-6">
              <div className="space-y-4">
                <Textarea
                  placeholder="Ask Millennium AI to write scripts, analyze code, or answer cybersecurity questions..."
                  value={aiPrompt}
                  onChange={(e) => setAiPrompt(e.target.value)}
                  className="bg-gray-800 border-gray-600 text-white min-h-[100px]"
                />
                <Button 
                  onClick={() => aiChat.mutate(aiPrompt)}
                  disabled={aiChat.isPending || !aiPrompt.trim()}
                  className="w-full bg-cyan-600 hover:bg-cyan-700"
                >
                  <MessageSquare className="w-4 h-4 mr-2" />
                  {aiChat.isPending ? 'Processing...' : 'Ask Millennium AI'}
                </Button>

                {aiResponse && (
                  <div className="mt-4 p-4 bg-gray-800 rounded border border-cyan-500/30">
                    <pre className="whitespace-pre-wrap text-sm text-gray-200">{aiResponse}</pre>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Products Section */}
        <section className="grid md:grid-cols-2 gap-8 mb-16">
          {/* Millennium RAT */}
          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur overflow-hidden">
            <CardHeader className="text-center p-4">
              <div className="relative w-full h-48 mb-4 rounded-lg overflow-hidden">
                <img 
                  src="https://i.ibb.co/v65ppyX/rat-interface.png" 
                  alt="Millennium RAT" 
                  className="w-full h-full object-contain bg-gray-800"
                />
              </div>
              <CardTitle className="text-xl sm:text-2xl text-cyan-400">Millennium RAT</CardTitle>
              <p className="text-sm sm:text-base text-gray-300">Advanced Remote Access Tool with Telegram C2</p>
            </CardHeader>
            <CardContent className="p-4">
              <ul className="space-y-1 text-xs sm:text-sm text-gray-300 mb-4">
                <li>• Telegram-based command & control</li>
                <li>• Advanced persistence mechanisms</li>
                <li>• Real-time screen capture</li>
                <li>• Keylogger & data exfiltration</li>
                <li>• Anti-detection techniques</li>
              </ul>
              <Button 
                onClick={() => window.open('https://t.me/milleniumrat', '_blank')}
                className="w-full bg-blue-600 hover:bg-blue-700 text-sm"
              >
                <Send className="w-4 h-4 mr-2" />
                Contact on Telegram
              </Button>
            </CardContent>
          </Card>

          {/* Dot Stealer */}
          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur overflow-hidden">
            <CardHeader className="text-center p-4">
              <div className="relative w-full h-48 mb-4 rounded-lg overflow-hidden">
                <img 
                  src="https://i.ibb.co/FkRMZ6B/dot-stealer.png" 
                  alt="Dot Stealer" 
                  className="w-full h-full object-contain bg-gray-800"
                />
              </div>
              <CardTitle className="text-xl sm:text-2xl text-cyan-400">Dot Stealer</CardTitle>
              <p className="text-sm sm:text-base text-gray-300">Advanced Data Extraction Framework</p>
            </CardHeader>
            <CardContent className="p-4">
              <ul className="space-y-1 text-xs sm:text-sm text-gray-300 mb-4">
                <li>• Browser credentials & cookies</li>
                <li>• Discord & Telegram sessions</li>
                <li>• Cryptocurrency wallets</li>
                <li>• System information gathering</li>
                <li>• Anti-VM & debugging protection</li>
              </ul>
              <Button 
                onClick={() => window.open('https://t.me/milleniumrat', '_blank')}
                className="w-full bg-blue-600 hover:bg-blue-700 text-sm"
              >
                <Send className="w-4 h-4 mr-2" />
                Contact on Telegram
              </Button>
            </CardContent>
          </Card>
        </section>

{/* Features Section */}
        <section className="py-20 bg-gray-900">
          <div className="container mx-auto px-4">
            <h2 className="text-3xl font-bold text-center mb-12 text-cyan-400">
              Professional Cybersecurity Toolkit
            </h2>

            {/* Main Feature Showcase */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 mb-16">
              <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-8 border border-cyan-500/30">
                <div className="flex items-center mb-6">
                  <Bot className="w-8 h-8 text-cyan-400 mr-3" />
                  <h3 className="text-2xl font-bold text-cyan-400">Millennium RAT System</h3>
                </div>
                <img 
                  src="https://i.ibb.co/v65ppyX/rat-interface.png" 
                  alt="Millennium RAT Interface" 
                  className="w-full h-48 object-cover rounded-lg mb-4 border border-cyan-500/20"
                />
                <p className="text-gray-300 mb-4">
                  Advanced remote access tool with comprehensive C&C capabilities, 
                  Telegram integration, and real-time monitoring.
                </p>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-700/50 p-3 rounded border border-cyan-500/20">
                    <Shield className="w-5 h-5 text-cyan-400 mb-2" />
                    <p className="text-xs text-gray-300">Stealth Operations</p>
                  </div>
                  <div className="bg-gray-700/50 p-3 rounded border border-cyan-500/20">
                    <Network className="w-5 h-5 text-cyan-400 mb-2" />
                    <p className="text-xs text-gray-300">C&C Server</p>
                  </div>
                </div>
              </div>

              <div className="bg-gradient-to-br from-gray-800 to-gray-900 rounded-xl p-8 border border-green-500/30">
                <div className="flex items-center mb-6">
                  <Zap className="w-8 h-8 text-green-400 mr-3" />
                  <h3 className="text-2xl font-bold text-green-400">Data Stealer Suite</h3>
                </div>
                <img 
                  src="https://i.ibb.co/FkRMZ6B/dot-stealer.png" 
                  alt="Data Stealer Interface" 
                  className="w-full h-48 object-cover rounded-lg mb-4 border border-green-500/20"
                />
                <p className="text-gray-300 mb-4">
                  Comprehensive data collection system similar to Redline, 
                  with encrypted reporting to Telegram in ZIP format.
                </p>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-700/50 p-3 rounded border border-green-500/20">
                    <Key className="w-5 h-5 text-green-400 mb-2" />
                    <p className="text-xs text-gray-300">Password Extraction</p>
                  </div>
                  <div className="bg-gray-700/50 p-3 rounded border border-green-500/20">
                    <FileCode className="w-5 h-5 text-green-400 mb-2" />
                    <p className="text-xs text-gray-300">Crypto Wallets</p>
                  </div>
                </div>
              </div>
            </div>

        {/* Script Tools Section */}
        <section className="mb-16">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-cyan-400 mb-4">Script Processing Tools</h2>
            <p className="text-gray-300">Advanced tools for script analysis, optimization, and protection</p>
          </div>

          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur">
            <CardContent className="p-4 sm:p-6">
              <div className="space-y-6">
                {/* Tool Selection - Mobile Responsive */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {scriptTools.map(tool => (
                    <Button
                      key={tool.id}
                      onClick={() => setSelectedTool(tool.id)}
                      variant={selectedTool === tool.id ? "default" : "outline"}
                      className={`p-4 h-auto flex flex-col items-center space-y-2 ${
                        selectedTool === tool.id 
                          ? 'bg-cyan-600 hover:bg-cyan-700 border-cyan-500' 
                          : 'border-gray-600 hover:border-cyan-500'
                      }`}
                    >
                      <tool.icon className="w-6 h-6" />
                      <div className="text-center">
                        <div className="font-medium text-sm">{tool.label}</div>
                        <div className="text-xs text-gray-400 mt-1">{tool.description}</div>
                      </div>
                    </Button>
                  ))}
                </div>

                {/* Processing Chain */}
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-600">
                  <h3 className="text-lg font-semibold text-cyan-400 mb-3">Processing Chain</h3>
                  <div className="text-sm text-gray-300 mb-3">
                    Apply multiple tools in sequence for advanced obfuscation
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {scriptTools.map(tool => (
                      <Button
                        key={`chain-${tool.id}`}
                        size="sm"
                        variant="outline"
                        className="border-gray-600 text-xs"
                        onClick={() => {
                          // Add to processing chain logic here
                        }}
                      >
                        <tool.icon className="w-3 h-3 mr-1" />
                        {tool.label}
                      </Button>
                    ))}
                  </div>
                </div>

                {/* Script Input/Output - Responsive Layout */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium text-gray-300">Input Script</label>
                      <Button 
                        size="sm" 
                        variant="outline" 
                        className="border-gray-600 text-xs"
                        onClick={() => {
                          const input = document.createElement('input');
                          input.type = 'file';
                          input.accept = '.js,.py,.php,.ps1,.bat,.sh';
                          input.onchange = (e) => {
                            const file = (e.target as HTMLInputElement).files?.[0];
                            if (file) {
                              const reader = new FileReader();
                              reader.onload = (e) => setScriptInput(e.target?.result as string);
                              reader.readAsText(file);
                            }
                          };
                          input.click();
                        }}
                      >
                        <Upload className="w-3 h-3 mr-1" />
                        Upload
                      </Button>
                    </div>
                    <Textarea
                      placeholder="Paste your script here or upload a file..."
                      value={scriptInput}
                      onChange={(e) => setScriptInput(e.target.value)}
                      className="bg-gray-800 border-gray-600 text-white h-64 sm:h-80 font-mono text-xs sm:text-sm"
                    />
                  </div>

                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <label className="text-sm font-medium text-gray-300">Processed Output</label>
                      {scriptOutput && (
                        <Button 
                          size="sm" 
                          variant="outline" 
                          className="border-gray-600 text-xs"
                          onClick={() => {
                            const blob = new Blob([scriptOutput], { type: 'text/plain' });
                            const url = URL.createObjectURL(blob);
                            const link = document.createElement('a');
                            link.href = url;
                            link.download = `processed_${selectedTool}_${Date.now()}.txt`;
                            link.click();
                            URL.revokeObjectURL(url);
                          }}
                        >
                          <Download className="w-3 h-3 mr-1" />
                          Download
                        </Button>
                      )}
                    </div>
                    <Textarea
                      value={scriptOutput}
                      readOnly
                      className="bg-gray-800 border-gray-600 text-white h-64 sm:h-80 font-mono text-xs sm:text-sm"
                      placeholder="Processed script will appear here..."
                    />
                  </div>
                </div>

                {/* Action Buttons - Mobile Responsive */}
                <div className="flex flex-col sm:flex-row gap-3">
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
                      setScriptInput('');
                      setScriptOutput('');
                    }}
                  >
                    Clear
                  </Button>

                  <Select value={selectedTool} onValueChange={setSelectedTool}>
                    <SelectTrigger className="bg-gray-800 border-gray-600 w-full sm:w-48">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {scriptTools.map(tool => (
                        <SelectItem key={tool.id} value={tool.id}>
                          {tool.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* Real-time Processing Stats */}
                {scriptInput && (
                  <div className="bg-blue-900/20 border border-blue-500/30 rounded p-3">
                    <div className="flex flex-wrap gap-4 text-sm">
                      <div className="text-blue-400">
                        Input: {scriptInput.length} characters
                      </div>
                      <div className="text-blue-400">
                        Lines: {scriptInput.split('\n').length}
                      </div>
                      {scriptOutput && (
                        <>
                          <div className="text-green-400">
                            Output: {scriptOutput.length} characters
                          </div>
                          <div className="text-green-400">
                            Reduction: {((scriptInput.length - scriptOutput.length) / scriptInput.length * 100).toFixed(1)}%
                          </div>
                        </>
                      )}
                    </div>

                    {/* Processing Metadata */}
                    {scriptProcessor.data?.metadata && (
                      <div className="mt-3 p-2 bg-gray-800/50 rounded border border-cyan-500/20">
                        <div className="text-xs text-cyan-400 font-semibold mb-1">Processing Details:</div>
                        <div className="text-xs text-gray-300">
                          Tool: {scriptProcessor.data.metadata.tool} | 
                          {scriptProcessor.data.metadata.reduction && ` Size Reduction: ${scriptProcessor.data.metadata.reduction}`}
                          {scriptProcessor.data.metadata.method && ` Method: ${scriptProcessor.data.metadata.method}`}
                          {scriptProcessor.data.metadata.protection && ` Protection: ${scriptProcessor.data.metadata.protection}`}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Advanced Polymorphic Crypter */}
        <section className="mb-16">
          <div className="text-center mb-8">
            <h2 className="text-2xl sm:text-3xl font-bold text-cyan-400 mb-4">Advanced Polymorphic Crypter</h2>
            <p className="text-sm sm:text-base text-gray-300">Military-grade executable protection for .NET and native binaries</p>
          </div>

          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur">
            <CardContent className="p-4 sm:p-6">
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
                <div className="space-y-3 sm:space-y-4">
                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-gray-300 mb-2">Upload Executable</label>
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      accept=".exe,.dll,.net"
                      className="hidden"
                    />
                    <Button
                      onClick={() => fileInputRef.current?.click()}
                      variant="outline"
                      className="w-full border-gray-600 text-gray-300 text-xs sm:text-sm py-2 px-3"
                    >
                      <Upload className="w-3 h-3 sm:w-4 sm:h-4 mr-2" />
                      <span className="truncate">
                        {crypterConfig.inputFile ? crypterConfig.inputFile.name : 'Select File'}
                      </span>
                    </Button>
                  </div>

                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-gray-300 mb-2">Output Name</label>
                    <Input
                      value={crypterConfig.outputName}
                      onChange={(e) => setCrypterConfig(prev => ({ ...prev, outputName: e.target.value }))}
                      className="bg-gray-800 border-gray-600 text-white text-xs sm:text-sm"
                      placeholder="protected_executable"
                    />
                  </div>

                  <div>
                    <label className="block text-xs sm:text-sm font-medium text-gray-300 mb-2">Compression Level</label>
                    <Select 
                      value={crypterConfig.compressionLevel} 
                      onValueChange={(value) => setCrypterConfig(prev => ({ ...prev, compressionLevel: value }))}
                    >
                      <SelectTrigger className="bg-gray-800 border-gray-600 text-white text-xs sm:text-sm">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="low">Low (Fast)</SelectItem>
                        <SelectItem value="medium">Medium</SelectItem>
                        <SelectItem value="high">High (Best)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="space-y-3 sm:space-y-4">
                  <h3 className="text-sm sm:text-lg font-semibold text-cyan-400">Protection Features</h3>

                  <div className="space-y-2 sm:space-y-3">
                    <label className="flex items-center space-x-2 sm:space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.antiDebug}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, antiDebug: e.target.checked }))}
                        className="w-3 h-3 sm:w-4 sm:h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300 text-xs sm:text-sm">Anti-Debug Protection</span>
                    </label>

                    <label className="flex items-center space-x-2 sm:space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.antiVM}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, antiVM: e.target.checked }))}
                        className="w-3 h-3 sm:w-4 sm:h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300 text-xs sm:text-sm">Anti-VM Detection</span>
                    </label>

                    <label className="flex items-center space-x-2 sm:space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.polymorphic}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, polymorphic: e.target.checked }))}
                        className="w-3 h-3 sm:w-4 sm:h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300 text-xs sm:text-sm">Polymorphic Engine</span>
                    </label>

                    <label className="flex items-center space-x-2 sm:space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.dotNetSupport}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, dotNetSupport: e.target.checked }))}
                        className="w-3 h-3 sm:w-4 sm:h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300 text-xs sm:text-sm">.NET Assembly Support</span>
                    </label>
                  </div>

                  {compileStep === 'encrypt' ? (
                    <Button
                      onClick={handleCrypterSubmit}
                      disabled={crypterProcessor.isPending || !crypterConfig.inputFile}
                      className="w-full bg-cyan-600 hover:bg-cyan-700 mt-4"
                    >
                      <Package className="w-4 h-4 mr-2" />
                      {crypterProcessor.isPending ? 'Encrypting...' : 'Step 1: Encrypt & Generate Stub'}
                    </Button>
                  ) : (
                    <div className="space-y-4 mt-4">
                      <div className="p-4 bg-green-900/20 border border-green-500/30 rounded">
                        <p className="text-green-400 font-medium">✓ Python stub generated: {cryptedFilename}</p>
                        <p className="text-gray-300 text-sm mt-1">Ready for compilation to Windows executable</p>
                      </div>

                      <div className="grid grid-cols-2 gap-4">
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" defaultChecked className="w-4 h-4 text-cyan-600" />
                          <span className="text-gray-300 text-sm">Hidden Imports</span>
                        </label>
                        <label className="flex items-center space-x-2">
                          <input type="checkbox" className="w-4 h-4 text-cyan-600" />
                          <span className="text-gray-300 text-sm">UPX Compression</span>
                        </label>
                      </div>

                      <div className="flex space-x-2">
                        <Button
                          onClick={() => executableCompiler.mutate({ 
                            filename: cryptedFilename, 
                            compileOptions: { hiddenImports: true } 
                          })}
                          disabled={executableCompiler.isPending}
                          className="flex-1 bg-green-600 hover:bg-green-700"
                        >
                          <Download className="w-4 h-4 mr-2" />
                          {executableCompiler.isPending ? 'Compiling...' : 'Step 2: Compile to EXE'}
                        </Button>
                        <Button
                          onClick={() => {
                            const link = document.createElement('a');
                            link.href = `/download/${cryptedFilename}`;
                            link.download = cryptedFilename;
                            link.click();
                          }}
                          variant="outline"
                          className="border-gray-600"
                        >
                          <FileCode className="w-4 h-4 mr-2" />
                          Download Python
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <Alert className="mt-6 border-yellow-500/30 bg-yellow-500/10">
                <Shield className="h-4 w-4" />
                <AlertDescription className="text-yellow-200">
                  <strong>Security Notice:</strong> This crypter generates FUD (Fully Undetectable) executables. 
                  Use only for authorized penetration testing and security research.
                </AlertDescription>
              </Alert>
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
              Version 4.0 - Professional Edition
            </Badge>
          </div>
          <p className="text-gray-400 text-sm">
            © 2025 Millennium Framework. For authorized cybersecurity research only.
          </p>
        </footer>
      </div>

      {/* Hidden Admin Access - Shield Icon */}
      <div 
        className="fixed bottom-4 right-4 z-50 cursor-pointer opacity-30 hover:opacity-100 transition-opacity duration-300"
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