import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import { Shield } from "lucide-react";

interface AdminLoginModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function AdminLoginModal({ isOpen, onClose }: AdminLoginModalProps) {
  const { toast } = useToast();
  const [credentials, setCredentials] = useState({
    username: "",
    password: "",
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    
    // Demo credentials check
    if (credentials.username === 'admin' && credentials.password === 'elite123') {
      onClose();
      setCredentials({ username: "", password: "" });
      window.location.href = '/admin-dashboard';
      console.log('Admin session started - redirecting to dashboard');
    } else {
      toast({
        title: "Access Denied",
        description: "Invalid credentials",
        variant: "destructive",
      });
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="bg-panel border-matrix/30 text-matrix max-w-md">
        <DialogHeader className="text-center space-y-4">
          <Shield className="w-12 h-12 text-matrix mx-auto" />
          <DialogTitle className="text-xl font-mono font-bold text-matrix">
            Admin Portal Access
          </DialogTitle>
          <p className="text-gray-400 text-sm">Authorized personnel only</p>
        </DialogHeader>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="modal-username" className="text-matrix font-mono">
              Username
            </Label>
            <Input
              id="modal-username"
              type="text"
              value={credentials.username}
              onChange={(e) => setCredentials(prev => ({ ...prev, username: e.target.value }))}
              className="bg-terminal border-matrix/30 text-matrix font-mono focus:border-matrix"
              placeholder="Username"
              required
            />
          </div>
          
          <div className="space-y-2">
            <Label htmlFor="modal-password" className="text-matrix font-mono">
              Password
            </Label>
            <Input
              id="modal-password"
              type="password"
              value={credentials.password}
              onChange={(e) => setCredentials(prev => ({ ...prev, password: e.target.value }))}
              className="bg-terminal border-matrix/30 text-matrix font-mono focus:border-matrix"
              placeholder="Password"
              required
            />
          </div>
          
          <div className="flex gap-3 pt-4">
            <Button type="submit" className="flex-1 cyber-button">
              Access Portal
            </Button>
            <Button 
              type="button" 
              variant="outline"
              className="flex-1 border-matrix text-matrix hover:bg-matrix/10"
              onClick={onClose}
            >
              Cancel
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
