import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { MapPin } from "lucide-react";
import type { Visitor } from "@shared/schema";

interface VisitorTrackingProps {
  visitors: Visitor[];
  isActive: boolean;
}

export default function VisitorTracking({ visitors, isActive }: VisitorTrackingProps) {
  const formatTimestamp = (timestamp: Date) => {
    return new Date(timestamp).toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit'
    });
  };

  const getStatusBadge = (visitor: Visitor) => {
    const lastSeen = new Date(visitor.lastSeen);
    const now = new Date();
    const timeDiff = now.getTime() - lastSeen.getTime();
    const isActive = timeDiff < 5 * 60 * 1000; // 5 minutes

    return (
      <Badge className={`${isActive ? 'bg-matrix/20 text-matrix' : 'bg-warning/20 text-warning'} text-xs font-mono`}>
        {isActive ? 'ACTIVE' : 'IDLE'}
      </Badge>
    );
  };

  return (
    <Card className="bg-panel border-matrix/20">
      <CardHeader>
        <CardTitle className="font-mono text-matrix text-lg flex items-center justify-between">
          <div className="flex items-center">
            <MapPin className="w-5 h-5 mr-2" />
            Visitor Geolocation
          </div>
          <Badge className={`${isActive ? 'bg-matrix/20 text-matrix' : 'bg-danger/20 text-danger'} font-mono text-xs`}>
            {isActive ? 'TRACKING' : 'DISABLED'}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3 h-64 overflow-y-auto">
          {visitors.length === 0 ? (
            <div className="text-gray-500 text-center py-8">
              {isActive ? 'No visitors detected' : 'Visitor tracking disabled'}
            </div>
          ) : (
            visitors.map((visitor) => (
              <Card key={visitor.id} className="bg-terminal border-matrix/30 p-3">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="font-mono text-matrix text-sm">
                      {visitor.ipAddress}
                    </div>
                    <div className="text-gray-400 text-xs">
                      {visitor.city}, {visitor.country}
                    </div>
                    {visitor.userAgent && (
                      <div className="text-accent text-xs mt-1 truncate">
                        {visitor.userAgent.slice(0, 60)}...
                      </div>
                    )}
                    {visitor.cookieConsent !== null && (
                      <div className="text-xs mt-1">
                        <span className="text-gray-500">Cookies: </span>
                        <span className={visitor.cookieConsent ? 'text-matrix' : 'text-warning'}>
                          {visitor.cookieConsent ? 'Accepted' : 'Declined'}
                        </span>
                      </div>
                    )}
                  </div>
                  <div className="text-right flex flex-col items-end gap-1">
                    <div className="font-mono text-matrix text-xs">
                      {formatTimestamp(visitor.lastSeen)}
                    </div>
                    {getStatusBadge(visitor)}
                  </div>
                </div>
              </Card>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}
