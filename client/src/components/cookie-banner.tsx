import { useState, useEffect } from "react";
import { useMutation } from "@tanstack/react-query";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { apiRequest } from "@/lib/queryClient";
import { Shield } from "lucide-react";

export default function CookieBanner() {
  const [isVisible, setIsVisible] = useState(false);
  const [hasInteracted, setHasInteracted] = useState(false);

  const consentMutation = useMutation({
    mutationFn: async (consent: boolean) => {
      const response = await apiRequest("POST", "/api/cookie-consent", { consent });
      return response.json();
    },
  });

  useEffect(() => {
    const cookiesAccepted = localStorage.getItem('cookiesAccepted');
    if (!cookiesAccepted && !hasInteracted) {
      setTimeout(() => {
        setIsVisible(true);
      }, 1000);
    }
  }, [hasInteracted]);

  const handleAccept = () => {
    localStorage.setItem('cookiesAccepted', 'true');
    setIsVisible(false);
    setHasInteracted(true);
    consentMutation.mutate(true);
    
    // Start educational tracking simulation
    console.log('Educational tracking simulation started');
  };

  const handleDecline = () => {
    localStorage.setItem('cookiesAccepted', 'false');
    setIsVisible(false);
    setHasInteracted(true);
    consentMutation.mutate(false);
  };

  if (!isVisible) return null;

  return (
    <div 
      className={`fixed top-0 left-0 right-0 bg-panel border-b border-matrix/30 p-4 z-50 transition-transform duration-500 ${
        isVisible ? 'translate-y-0' : '-translate-y-full'
      }`}
    >
      <Card className="max-w-6xl mx-auto bg-transparent border-none">
        <CardContent className="flex flex-col md:flex-row items-center justify-between gap-4 p-0">
          <div className="text-sm text-gray-300 flex items-center">
            <Shield className="text-matrix mr-2 w-4 h-4" />
            This site uses cookies for session tracking demonstrations and analytics. 
            By continuing, you consent to educational monitoring.
          </div>
          <div className="flex gap-3">
            <Button 
              onClick={handleAccept}
              className="cyber-button text-sm px-4 py-2"
              disabled={consentMutation.isPending}
            >
              Accept & Track
            </Button>
            <Button 
              onClick={handleDecline}
              variant="outline"
              className="border-matrix text-matrix px-4 py-2 text-sm font-mono hover:bg-matrix/10"
              disabled={consentMutation.isPending}
            >
              Decline
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
