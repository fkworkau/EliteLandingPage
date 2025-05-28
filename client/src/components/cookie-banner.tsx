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
      className={`fixed bottom-5 right-5 bg-black/80 border border-gray-600 p-2 z-50 transition-transform duration-500 rounded-lg max-w-sm ${
        isVisible ? 'translate-x-0' : 'translate-x-full'
      }`}
    >
      <Card className="bg-transparent border-none">
        <CardContent className="flex flex-col gap-2 p-0">
          <div className="text-xs text-black opacity-60">
            <Shield className="text-black mr-1 w-3 h-3 inline opacity-60" />
            This site uses cookies for analytics
          </div>
          <div className="flex gap-2">
            <Button 
              onClick={handleAccept}
              className="bg-gray-700 text-black text-xs px-2 py-1 h-auto hover:bg-gray-600"
              disabled={consentMutation.isPending}
            >
              Accept
            </Button>
            <Button 
              onClick={handleDecline}
              variant="outline"
              className="border-gray-600 text-black px-2 py-1 text-xs h-auto hover:bg-gray-700"
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
