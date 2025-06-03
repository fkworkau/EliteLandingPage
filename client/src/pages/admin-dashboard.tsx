import { useState, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useLocation } from "wouter";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import PacketCapture from "@/components/packet-capture";
import VisitorTracking from "@/components/visitor-tracking";
import GroqAIAnalysis from "@/components/groq-ai-analysis";
import MillenniumBuilder from "@/components/millennium-builder";
import PythonToolkitManager from "@/components/python-toolkit-manager";
import { useRealTimeData } from "@/hooks/useRealTimeData";
import { 
  Shield, 
  LogOut, 
  Activity, 
  Users, 
  Globe, 
  AlertTriangle,
  Power,
  RotateCcw,
  TrendingUp
} from "lucide-react";

export default function AdminDashboard() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [simulationStates, setSimulationStates] = useState({
    sessionHijacking: true,
    packetCapture: false,
    ipGeolocation: true,
  });

  // Check admin authentication
  const { data: adminUser, error: authError } = useQuery({
    queryKey: ["/api/admin/me"],
    retry: false,
  });

  // Get dashboard stats
  const { data: stats, refetch: refetchStats } = useQuery({
    queryKey: ["/api/admin/stats"],
    refetchInterval: 5000, // Refresh every 5 seconds
  });

  // Real-time data hook
  const { visitors, packets, isConnected } = useRealTimeData();

  // Logout mutation
  const logoutMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest("POST", "/api/admin/logout", {});
      return response.json();
    },
    onSuccess: () => {
      toast({
        title: "Logged Out",
        description: "Session terminated successfully",
      });
      setLocation("/");
    },
  });

  // Redirect if not authenticated
  useEffect(() => {
    if (authError || (!adminUser && authError?.message.includes("401"))) {
      setLocation("/admin-portal");
    }
  }, [authError, adminUser, setLocation]);

  const handleLogout = () => {
    logoutMutation.mutate();
  };

  const toggleSimulation = (type: keyof typeof simulationStates) => {
    setSimulationStates(prev => ({
      ...prev,
      [type]: !prev[type]
    }));
    
    toast({
      title: "Simulation Updated",
      description: `${type} ${simulationStates[type] ? 'disabled' : 'enabled'}`,
    });
  };

  const handleEmergencyStop = () => {
    setSimulationStates({
      sessionHijacking: false,
      packetCapture: false,
      ipGeolocation: false,
    });
    
    toast({
      title: "EMERGENCY STOP",
      description: "All monitoring systems disabled",
      variant: "destructive",
    });
  };

  const handleResetTracking = () => {
    toast({
      title: "Tracking Reset",
      description: "All tracking data cleared",
    });
    refetchStats();
  };

  if (!adminUser) {
    return (
      <div className="min-h-screen bg-terminal flex items-center justify-center">
        <div className="text-matrix font-mono">Authenticating...</div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-black">
      {/* Admin Header */}
      <header className="bg-black border-b border-gray-800 p-6 shadow-lg">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center space-x-6">
            <Shield className="text-green-400 w-8 h-8" />
            <h1 className="text-2xl font-bold text-white">Admin Control Panel</h1>
            <Badge className={`px-4 py-2 text-sm font-semibold rounded-full ${
              isConnected 
                ? 'bg-green-500/20 text-green-400 border border-green-500/30' 
                : 'bg-red-500/20 text-red-400 border border-red-500/30'
            }`}>
              {isConnected ? 'LIVE' : 'OFFLINE'}
            </Badge>
          </div>
          <div className="flex items-center space-x-6">
            <span className="text-gray-300">
              Welcome, <span className="text-white font-medium">{adminUser.username}</span>
            </span>
            <Button
              onClick={handleLogout}
              className="bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg font-medium"
              disabled={logoutMutation.isPending}
            >
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto p-6">
        {/* Stats Overview */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Active Sessions</p>
                <p className="text-2xl font-bold text-white">{stats?.activeSessions || 0}</p>
              </div>
              <Activity className="text-green-400 w-8 h-8" />
            </div>
          </div>
          
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Total Visitors</p>
                <p className="text-2xl font-bold text-white">{stats?.visitors?.total || 0}</p>
              </div>
              <Users className="text-blue-400 w-8 h-8" />
            </div>
          </div>
          
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Unique IPs</p>
                <p className="text-2xl font-bold text-white">{stats?.visitors?.unique || 0}</p>
              </div>
              <Globe className="text-purple-400 w-8 h-8" />
            </div>
          </div>
          
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-gray-400 text-sm">Countries</p>
                <p className="text-2xl font-bold text-white">{stats?.visitors?.countries || 0}</p>
              </div>
              <TrendingUp className="text-yellow-400 w-8 h-8" />
            </div>
          </div>
        </div>

        {/* Control Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
          {/* Simulation Controls */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center">
              <AlertTriangle className="text-yellow-400 w-6 h-6 mr-3" />
              Simulation Controls
            </h2>
            <div className="space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                <span className="text-gray-300 font-medium">Session Hijacking</span>
                <Button
                  className={`px-6 py-2 rounded-lg font-medium transition-colors ${
                    simulationStates.sessionHijacking 
                      ? 'bg-green-600 hover:bg-green-700 text-white' 
                      : 'bg-red-600 hover:bg-red-700 text-white'
                  }`}
                  onClick={() => toggleSimulation('sessionHijacking')}
                >
                  {simulationStates.sessionHijacking ? 'ON' : 'OFF'}
                </Button>
              </div>
              <div className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                <span className="text-gray-300 font-medium">Packet Capture</span>
                <Button
                  className={`px-6 py-2 rounded-lg font-medium transition-colors ${
                    simulationStates.packetCapture 
                      ? 'bg-green-600 hover:bg-green-700 text-white' 
                      : 'bg-red-600 hover:bg-red-700 text-white'
                  }`}
                  onClick={() => toggleSimulation('packetCapture')}
                >
                  {simulationStates.packetCapture ? 'ON' : 'OFF'}
                </Button>
              </div>
              <div className="flex items-center justify-between p-4 bg-gray-800 rounded-lg">
                <span className="text-gray-300 font-medium">IP Geolocation</span>
                <Button
                  className={`px-6 py-2 rounded-lg font-medium transition-colors ${
                    simulationStates.ipGeolocation 
                      ? 'bg-green-600 hover:bg-green-700 text-white' 
                      : 'bg-red-600 hover:bg-red-700 text-white'
                  }`}
                  onClick={() => toggleSimulation('ipGeolocation')}
                >
                  {simulationStates.ipGeolocation ? 'ON' : 'OFF'}
                </Button>
              </div>
            </div>
          </div>

          {/* Master Controls */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
            <h2 className="text-xl font-bold text-white mb-6 flex items-center">
              <Power className="text-red-400 w-6 h-6 mr-3" />
              Master Controls
            </h2>
            <div className="space-y-4">
              <Button 
                className="w-full bg-red-600 hover:bg-red-700 text-white py-4 rounded-lg font-medium text-lg"
                onClick={handleEmergencyStop}
              >
                <Power className="w-5 h-5 mr-3" />
                EMERGENCY STOP
              </Button>
              <Button 
                className="w-full bg-yellow-600 hover:bg-yellow-700 text-white py-4 rounded-lg font-medium text-lg"
                onClick={handleResetTracking}
              >
                <RotateCcw className="w-5 h-5 mr-3" />
                RESET TRACKING
              </Button>
            </div>
          </div>
        </div>

        {/* Tabbed Dashboard */}
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <Tabs defaultValue="monitoring" className="w-full">
            <div className="border-b border-gray-800">
              <TabsList className="grid w-full grid-cols-3 bg-transparent h-16">
                <TabsTrigger 
                  value="monitoring" 
                  className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-gray-800 h-full text-lg font-medium"
                >
                  Network Monitoring
                </TabsTrigger>
                <TabsTrigger 
                  value="builder" 
                  className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-gray-800 h-full text-lg font-medium"
                >
                  Millennium Builder
                </TabsTrigger>
                <TabsTrigger 
                  value="python" 
                  className="text-gray-300 data-[state=active]:text-white data-[state=active]:bg-gray-800 h-full text-lg font-medium"
                >
                  Python Toolkit
                </TabsTrigger>
              </TabsList>
            </div>
            
            <TabsContent value="monitoring" className="p-6">
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                <PacketCapture 
                  packets={packets} 
                  isActive={simulationStates.packetCapture}
                />
                <VisitorTracking 
                  visitors={visitors} 
                  isActive={simulationStates.ipGeolocation}
                />
              </div>
            </TabsContent>
            
            <TabsContent value="builder" className="p-6">
              <MillenniumBuilder />
            </TabsContent>
            
            <TabsContent value="python" className="p-6">
              <PythonToolkitManager />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </div>
  );
}
