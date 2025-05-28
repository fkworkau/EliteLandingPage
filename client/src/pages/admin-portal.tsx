import { useState } from "react";
import { useLocation } from "wouter";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Shield } from "lucide-react";

export default function AdminPortal() {
  const [, setLocation] = useLocation();
  const { toast } = useToast();
  const [credentials, setCredentials] = useState({
    username: "",
    password: "",
  });

  const loginMutation = useMutation({
    mutationFn: async (data: { username: string; password: string }) => {
      const response = await apiRequest("POST", "/api/admin/login", data);
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Access Granted",
        description: "Welcome to the Admin Control Panel",
      });
      setLocation("/admin-dashboard");
    },
    onError: (error: any) => {
      toast({
        title: "Access Denied",
        description: error.message || "Invalid credentials",
        variant: "destructive",
      });
    },
  });

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault();
    if (!credentials.username || !credentials.password) {
      toast({
        title: "Error",
        description: "Please enter both username and password",
        variant: "destructive",
      });
      return;
    }
    loginMutation.mutate(credentials);
  };

  return (
    <div className="min-h-screen bg-terminal flex items-center justify-center px-4">
      <Card className="w-full max-w-md bg-panel border-matrix/30">
        <CardHeader className="text-center space-y-4">
          <Shield className="w-12 h-12 text-matrix mx-auto" />
          <CardTitle className="text-2xl font-mono font-bold text-matrix">
            Admin Portal Access
          </CardTitle>
          <p className="text-gray-400 text-sm">Authorized personnel only</p>
        </CardHeader>
        
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="username" className="text-matrix font-mono">
                Username
              </Label>
              <Input
                id="username"
                type="text"
                value={credentials.username}
                onChange={(e) => setCredentials(prev => ({ ...prev, username: e.target.value }))}
                className="bg-terminal border-matrix/30 text-matrix font-mono focus:border-matrix"
                placeholder="Enter username"
                required
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="password" className="text-matrix font-mono">
                Password
              </Label>
              <Input
                id="password"
                type="password"
                value={credentials.password}
                onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
                className="bg-terminal border-matrix/30 text-matrix font-mono focus:border-matrix"
                placeholder="Enter password"
                required
              />
            </div>
            
            <div className="flex gap-3 pt-4">
              <Button 
                type="submit" 
                className="flex-1 cyber-button"
                disabled={loginMutation.isPending}
              >
                {loginMutation.isPending ? "Authenticating..." : "Access Portal"}
              </Button>
              <Button 
                type="button" 
                variant="outline"
                className="flex-1 border-matrix text-matrix hover:bg-matrix/10"
                onClick={() => setLocation("/")}
              >
                Cancel
              </Button>
            </div>
          </form>
          
          <div className="mt-6 p-4 bg-matrix/10 border border-matrix/30 rounded text-center">
            <p className="text-gray-400 text-xs font-mono">
              Demo Credentials: admin / elite123
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
