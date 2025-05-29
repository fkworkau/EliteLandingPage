
import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Cookie, X } from "lucide-react";

export default function CookieBanner() {
  const [isVisible, setIsVisible] = useState(false);
  const [browserData, setBrowserData] = useState<any>(null);

  useEffect(() => {
    // Check if user has already responded to cookies
    const cookieConsent = localStorage.getItem('cookieConsent');
    if (!cookieConsent) {
      setIsVisible(true);
      collectBrowserData();
    }
  }, []);

  const collectBrowserData = () => {
    const data = {
      userAgent: navigator.userAgent,
      language: navigator.language,
      languages: navigator.languages,
      platform: navigator.platform,
      cookieEnabled: navigator.cookieEnabled,
      onLine: navigator.onLine,
      doNotTrack: navigator.doNotTrack,
      hardwareConcurrency: navigator.hardwareConcurrency,
      maxTouchPoints: navigator.maxTouchPoints,
      screen: {
        width: screen.width,
        height: screen.height,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
      },
      window: {
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
      },
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timestamp: new Date().toISOString(),
    };
    setBrowserData(data);
  };

  const handleConsent = async (accepted: boolean) => {
    localStorage.setItem('cookieConsent', accepted ? 'true' : 'false');
    
    // Send browser data to server
    if (browserData) {
      try {
        await fetch('/api/cookie-consent', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            ...browserData,
            consent: accepted,
          }),
        });
      } catch (error) {
        console.error('Failed to send browser data:', error);
      }
    }
    
    setIsVisible(false);
  };

  if (!isVisible) return null;

  return (
    <div className="fixed bottom-4 left-4 right-4 z-50 md:left-auto md:max-w-md">
      <Card className="bg-gray-900 border-matrix p-4">
        <div className="flex items-start gap-3">
          <Cookie className="w-6 h-6 text-matrix flex-shrink-0 mt-1" />
          <div className="flex-1">
            <h3 className="font-semibold text-white mb-2">Educational Cookie Notice</h3>
            <p className="text-sm text-gray-300 mb-4">
              This cybersecurity training platform uses cookies and collects browser data for educational purposes. 
              Your data helps demonstrate tracking techniques used in security research.
            </p>
            <div className="flex gap-2">
              <Button 
                size="sm" 
                className="bg-matrix text-black hover:bg-green-400"
                onClick={() => handleConsent(true)}
              >
                Accept & Learn
              </Button>
              <Button 
                size="sm" 
                variant="outline" 
                className="border-gray-600 text-gray-300"
                onClick={() => handleConsent(false)}
              >
                Decline
              </Button>
            </div>
          </div>
          <Button 
            size="sm" 
            variant="ghost" 
            className="text-gray-400 hover:text-white p-1"
            onClick={() => setIsVisible(false)}
          >
            <X className="w-4 h-4" />
          </Button>
        </div>
      </Card>
    </div>
  );
}
