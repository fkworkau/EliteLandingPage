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
    <div className="min-h-screen bg-terminal">
      {/* Admin Header */}
      <header className="bg-panel border-b border-matrix/30 p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Shield className="text-matrix text-xl" />
            <span className="font-mono text-lg font-bold text-matrix">ADMIN CONTROL PANEL</span>
            <Badge className={`${isConnected ? 'bg-matrix/20 text-matrix' : 'bg-danger/20 text-danger'} px-3 py-1 text-sm font-mono`}>
              {isConnected ? 'LIVE' : 'OFFLINE'}
            </Badge>
          </div>
          <div className="flex items-center space-x-4">
            <span className="text-gray-400 font-mono text-sm">
              Welcome, {adminUser.username}
            </span>
            <Button
              onClick={handleLogout}
              className="cyber-button-danger text-sm"
              disabled={logoutMutation.isPending}
            >
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </Button>
          </div>
        </div>
      </header>

      {/* Admin Content */}
      <div className="p-6">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Real-time Stats */}
          <Card className="bg-panel border-matrix/20">
            <CardHeader>
              <CardTitle className="font-mono text-matrix text-lg flex items-center">
                <TrendingUp className="w-5 h-5 mr-2" />
                Live Analytics
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex justify-between">
                <span className="text-gray-400">Active Sessions:</span>
                <span className="font-mono text-matrix">{stats?.activeSessions || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Total Visitors:</span>
                <span className="font-mono text-matrix">{stats?.visitors?.total || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Unique IPs:</span>
                <span className="font-mono text-matrix">{stats?.visitors?.unique || 0}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-400">Countries:</span>
                <span className="font-mono text-matrix">{stats?.visitors?.countries || 0}</span>
              </div>
            </CardContent>
          </Card>

          {/* Threat Simulation Controls */}
          <Card className="bg-panel border-matrix/20">
            <CardHeader>
              <CardTitle className="font-mono text-matrix text-lg flex items-center">
                <AlertTriangle className="w-5 h-5 mr-2" />
                Simulation Controls
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Session Hijacking:</span>
                <Button
                  size="sm"
                  className={`px-3 py-1 text-xs font-mono ${
                    simulationStates.sessionHijacking 
                      ? 'cyber-button' 
                      : 'cyber-button-danger'
                  }`}
                  onClick={() => toggleSimulation('sessionHijacking')}
                >
                  {simulationStates.sessionHijacking ? 'ON' : 'OFF'}
                </Button>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Packet Capture:</span>
                <Button
                  size="sm"
                  className={`px-3 py-1 text-xs font-mono ${
                    simulationStates.packetCapture 
                      ? 'cyber-button' 
                      : 'cyber-button-danger'
                  }`}
                  onClick={() => toggleSimulation('packetCapture')}
                >
                  {simulationStates.packetCapture ? 'ON' : 'OFF'}
                </Button>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">IP Geolocation:</span>
                <Button
                  size="sm"
                  className={`px-3 py-1 text-xs font-mono ${
                    simulationStates.ipGeolocation 
                      ? 'cyber-button' 
                      : 'cyber-button-danger'
                  }`}
                  onClick={() => toggleSimulation('ipGeolocation')}
                >
                  {simulationStates.ipGeolocation ? 'ON' : 'OFF'}
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Master Controls */}
          <Card className="bg-panel border-danger/20">
            <CardHeader>
              <CardTitle className="font-mono text-danger text-lg flex items-center">
                <Power className="w-5 h-5 mr-2" />
                Master Controls
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Button 
                className="w-full cyber-button-danger text-sm"
                onClick={handleEmergencyStop}
              >
                <Power className="w-4 h-4 mr-2" />
                EMERGENCY STOP
              </Button>
              <Button 
                className="w-full bg-warning text-terminal hover:bg-warning/80 font-mono text-sm"
                onClick={handleResetTracking}
              >
                <RotateCcw className="w-4 h-4 mr-2" />
                RESET TRACKING
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Network Monitoring Dashboard */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Packet Capture */}
          <PacketCapture 
            packets={packets} 
            isActive={simulationStates.packetCapture}
          />

          {/* Visitor Tracking */}
          <VisitorTracking 
            visitors={visitors} 
            isActive={simulationStates.ipGeolocation}
          />
        </div>
      </div>
    </div>
  );
}
