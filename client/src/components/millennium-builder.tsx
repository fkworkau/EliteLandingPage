import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Wrench, Download, Shield } from "lucide-react";

export default function MillenniumBuilder() {
  const { toast } = useToast();
  const [config, setConfig] = useState({
    serverIp: "0.0.0.0",
    serverPort: "8888",
    outputName: "millennium_agent",
    crypter: {
      enabled: true,
      antiDebug: true,
      antiVM: true,
      compression: true
    }
  });
  const [isCompiling, setIsCompiling] = useState(false);

  const handleCompile = async () => {
    setIsCompiling(true);
    try {
      const response = await apiRequest('POST', '/api/admin/compile-millennium-agent', {
        serverIp: config.serverIp,
        serverPort: config.serverPort,
        outputName: config.outputName,
        crypterOptions: config.crypter
      });

      const result = await response.json();

      if (result.success) {
        toast({
          title: "Compilation Successful",
          description: `Agent compiled: ${result.path}`,
        });
      } else {
        toast({
          title: "Compilation Failed",
          description: result.error || "Unknown error occurred",
          variant: "destructive",
        });
      }
    } catch (error) {
      toast({
        title: "Compilation Error",
        description: "Failed to compile agent",
        variant: "destructive",
      });
    }
    setIsCompiling(false);
  };

  return (
    <Card className="bg-terminal border-matrix">
      <CardHeader>
        <CardTitle className="text-matrix flex items-center gap-2">
          <Wrench className="w-5 h-5" />
          Millennium RAT Builder
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <Label htmlFor="serverIp" className="text-matrix">Server IP</Label>
            <Input
              id="serverIp"
              value={config.serverIp}
              onChange={(e) => setConfig(prev => ({ ...prev, serverIp: e.target.value }))}
              className="bg-black border-matrix text-matrix"
              placeholder="0.0.0.0"
            />
          </div>
          <div>
            <Label htmlFor="serverPort" className="text-matrix">Server Port</Label>
            <Input
              id="serverPort"
              value={config.serverPort}
              onChange={(e) => setConfig(prev => ({ ...prev, serverPort: e.target.value }))}
              className="bg-black border-matrix text-matrix"
              placeholder="8888"
            />
          </div>
        </div>

        <div>
          <Label htmlFor="outputName" className="text-matrix">Output Name</Label>
          <Input
            id="outputName"
            value={config.outputName}
            onChange={(e) => setConfig(prev => ({ ...prev, outputName: e.target.value }))}
            className="bg-black border-matrix text-matrix"
            placeholder="millennium_agent"
          />
        </div>

        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <Label htmlFor="crypter" className="text-matrix flex items-center gap-2">
              <Shield className="w-4 h-4" />
              Enable Crypter
            </Label>
            <Switch
              id="crypter"
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
            <div className="grid grid-cols-3 gap-4 pl-6">
              <div className="flex items-center space-x-2">
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
                <Label htmlFor="antiDebug" className="text-matrix text-sm">Anti-Debug</Label>
              </div>
              <div className="flex items-center space-x-2">
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
                <Label htmlFor="antiVM" className="text-matrix text-sm">Anti-VM</Label>
              </div>
              <div className="flex items-center space-x-2">
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
                <Label htmlFor="compression" className="text-matrix text-sm">Compression</Label>
              </div>
            </div>
          )}
        </div>

        <Button 
          onClick={handleCompile} 
          disabled={isCompiling}
          className="w-full bg-matrix text-black hover:bg-matrix/80"
        >
          {isCompiling ? (
            <>
              <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin mr-2" />
              Compiling...
            </>
          ) : (
            <>
              <Download className="w-4 h-4 mr-2" />
              Compile Agent
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}