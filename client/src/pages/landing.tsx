
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
    }
  });

  // Advanced Crypter
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
      // Trigger download of crypted executable
      const link = document.createElement('a');
      link.href = data.downloadUrl;
      link.download = data.filename;
      link.click();
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
        
        <Button 
          onClick={() => setShowAdminModal(true)}
          className="absolute top-4 right-4 bg-gray-800 hover:bg-gray-700"
        >
          <Settings className="w-4 h-4 mr-2" />
          Admin
        </Button>
      </header>

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
            <CardHeader className="text-center">
              <img 
                src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCADgAOADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAP..." 
                alt="Millennium RAT" 
                className="w-full h-48 object-cover rounded-lg mb-4"
              />
              <CardTitle className="text-2xl text-cyan-400">Millennium RAT</CardTitle>
              <p className="text-gray-300">Advanced Remote Access Tool with Telegram C2</p>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-gray-300 mb-4">
                <li>• Telegram-based command & control</li>
                <li>• Advanced persistence mechanisms</li>
                <li>• Real-time screen capture</li>
                <li>• Keylogger & data exfiltration</li>
                <li>• Anti-detection techniques</li>
              </ul>
              <div className="flex space-x-2">
                <Button className="flex-1 bg-blue-600 hover:bg-blue-700">
                  <Download className="w-4 h-4 mr-2" />
                  Download
                </Button>
                <Button variant="outline" className="border-cyan-500 text-cyan-400">
                  <Send className="w-4 h-4 mr-2" />
                  Telegram
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Dot Stealer */}
          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur overflow-hidden">
            <CardHeader className="text-center">
              <img 
                src="data:image/jpeg;base64,/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAYEBQYFBAYGBQYHBwYIChAKCgkJChQODwwQFxQYGBcUFhYaHSUfGhsjHBYWICwgIyYnKSopGR8tMC0oMCUoKSj/2wBDAQcHBwoIChMKChMoGhYaKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCj/wAARCADgAOADASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAP..." 
                alt="Dot Stealer" 
                className="w-full h-48 object-cover rounded-lg mb-4"
              />
              <CardTitle className="text-2xl text-cyan-400">Dot Stealer</CardTitle>
              <p className="text-gray-300">Advanced Data Extraction Framework</p>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm text-gray-300 mb-4">
                <li>• Browser credentials & cookies</li>
                <li>• Discord & Telegram sessions</li>
                <li>• Cryptocurrency wallets</li>
                <li>• System information gathering</li>
                <li>• Anti-VM & debugging protection</li>
              </ul>
              <div className="flex space-x-2">
                <Button className="flex-1 bg-blue-600 hover:bg-blue-700">
                  <Download className="w-4 h-4 mr-2" />
                  Download
                </Button>
                <Button variant="outline" className="border-cyan-500 text-cyan-400">
                  <Send className="w-4 h-4 mr-2" />
                  Telegram
                </Button>
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Script Tools Section */}
        <section className="mb-16">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-cyan-400 mb-4">Script Processing Tools</h2>
            <p className="text-gray-300">Advanced tools for script analysis, optimization, and protection</p>
          </div>

          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur">
            <CardContent className="p-6">
              <Tabs value={selectedTool} onValueChange={setSelectedTool}>
                <TabsList className="grid w-full grid-cols-4 bg-gray-800">
                  {scriptTools.map(tool => (
                    <TabsTrigger key={tool.id} value={tool.id} className="data-[state=active]:bg-cyan-600">
                      <tool.icon className="w-4 h-4 mr-2" />
                      {tool.label}
                    </TabsTrigger>
                  ))}
                </TabsList>

                {scriptTools.map(tool => (
                  <TabsContent key={tool.id} value={tool.id} className="mt-6">
                    <div className="space-y-4">
                      <p className="text-gray-300">{tool.description}</p>
                      
                      <div className="grid md:grid-cols-2 gap-4">
                        <div>
                          <label className="block text-sm font-medium text-gray-300 mb-2">Input Script</label>
                          <Textarea
                            placeholder="Paste your script here or upload a file..."
                            value={scriptInput}
                            onChange={(e) => setScriptInput(e.target.value)}
                            className="bg-gray-800 border-gray-600 text-white h-64 font-mono text-sm"
                          />
                        </div>
                        
                        <div>
                          <label className="block text-sm font-medium text-gray-300 mb-2">Processed Output</label>
                          <Textarea
                            value={scriptOutput}
                            readOnly
                            className="bg-gray-800 border-gray-600 text-white h-64 font-mono text-sm"
                            placeholder="Processed script will appear here..."
                          />
                        </div>
                      </div>

                      <div className="flex space-x-4">
                        <Button
                          onClick={() => scriptProcessor.mutate({ script: scriptInput, tool: selectedTool })}
                          disabled={scriptProcessor.isPending || !scriptInput.trim()}
                          className="bg-cyan-600 hover:bg-cyan-700"
                        >
                          <tool.icon className="w-4 h-4 mr-2" />
                          {scriptProcessor.isPending ? 'Processing...' : `Apply ${tool.label}`}
                        </Button>
                        
                        <Button variant="outline" className="border-gray-600">
                          <Upload className="w-4 h-4 mr-2" />
                          Upload File
                        </Button>
                        
                        {scriptOutput && (
                          <Button variant="outline" className="border-gray-600">
                            <Download className="w-4 h-4 mr-2" />
                            Download
                          </Button>
                        )}
                      </div>
                    </div>
                  </TabsContent>
                ))}
              </Tabs>
            </CardContent>
          </Card>
        </section>

        {/* Advanced Polymorphic Crypter */}
        <section className="mb-16">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-cyan-400 mb-4">Advanced Polymorphic Crypter</h2>
            <p className="text-gray-300">Military-grade executable protection for .NET and native binaries</p>
          </div>

          <Card className="bg-gray-900/50 border-cyan-500/30 backdrop-blur">
            <CardContent className="p-6">
              <div className="grid md:grid-cols-2 gap-6">
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Upload Executable</label>
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
                      className="w-full border-gray-600 text-gray-300"
                    >
                      <Upload className="w-4 h-4 mr-2" />
                      {crypterConfig.inputFile ? crypterConfig.inputFile.name : 'Select File'}
                    </Button>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Output Name</label>
                    <Input
                      value={crypterConfig.outputName}
                      onChange={(e) => setCrypterConfig(prev => ({ ...prev, outputName: e.target.value }))}
                      className="bg-gray-800 border-gray-600 text-white"
                      placeholder="protected_executable"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">Compression Level</label>
                    <Select 
                      value={crypterConfig.compressionLevel} 
                      onValueChange={(value) => setCrypterConfig(prev => ({ ...prev, compressionLevel: value }))}
                    >
                      <SelectTrigger className="bg-gray-800 border-gray-600 text-white">
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

                <div className="space-y-4">
                  <h3 className="text-lg font-semibold text-cyan-400">Protection Features</h3>
                  
                  <div className="space-y-3">
                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.antiDebug}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, antiDebug: e.target.checked }))}
                        className="w-4 h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300">Anti-Debug Protection</span>
                    </label>

                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.antiVM}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, antiVM: e.target.checked }))}
                        className="w-4 h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300">Anti-VM Detection</span>
                    </label>

                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.polymorphic}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, polymorphic: e.target.checked }))}
                        className="w-4 h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300">Polymorphic Engine</span>
                    </label>

                    <label className="flex items-center space-x-3">
                      <input
                        type="checkbox"
                        checked={crypterConfig.dotNetSupport}
                        onChange={(e) => setCrypterConfig(prev => ({ ...prev, dotNetSupport: e.target.checked }))}
                        className="w-4 h-4 text-cyan-600 rounded"
                      />
                      <span className="text-gray-300">.NET Assembly Support</span>
                    </label>
                  </div>

                  <Button
                    onClick={handleCrypterSubmit}
                    disabled={crypterProcessor.isPending || !crypterConfig.inputFile}
                    className="w-full bg-cyan-600 hover:bg-cyan-700 mt-4"
                  >
                    <Package className="w-4 h-4 mr-2" />
                    {crypterProcessor.isPending ? 'Processing...' : 'Generate Protected Executable'}
                  </Button>
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

      <AdminLoginModal 
        isOpen={showAdminModal} 
        onClose={() => setShowAdminModal(false)} 
      />
      <CookieBanner />
    </div>
  );
}
