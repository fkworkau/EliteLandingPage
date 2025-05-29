import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { MapPin } from "lucide-react";
import type { Visitor } from "@shared/schema";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Monitor, Globe, MapPin } from "lucide-react";
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
    <Card className="bg-terminal border-matrix">
      <CardHeader>
        <CardTitle className="text-matrix flex items-center gap-2">
          <Monitor className="w-5 h-5" />
          Live Visitor Tracking
          <Badge className={`ml-auto ${isActive ? 'bg-matrix text-black' : 'bg-gray-600 text-white'}`}>
            {isActive ? 'MONITORING' : 'PAUSED'}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-[400px]">
          <div className="space-y-2">
            {visitors.length === 0 ? (
              <div className="text-center py-8 text-gray-400">
                <Monitor className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No visitors detected yet</p>
                <p className="text-sm">Waiting for incoming connections...</p>
              </div>
            ) : (
              visitors.map((visitor) => (
                <div key={visitor.id} className="border border-matrix/30 rounded p-3 bg-black/50">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <Globe className="w-4 h-4 text-matrix" />
                      <span className="font-mono text-matrix">{visitor.ipAddress}</span>
                    </div>
                    {getStatusBadge(visitor)}
                  </div>
                  
                  <div className="space-y-1 text-sm">
                    <div className="flex items-center gap-2 text-gray-300">
                      <MapPin className="w-3 h-3" />
                      <span>{visitor.city}, {visitor.country}</span>
                    </div>
                    
                    <div className="text-gray-400 font-mono text-xs">
                      Session: {visitor.sessionId?.substring(0, 8)}...
                    </div>
                    
                    <div className="text-gray-400 text-xs">
                      First seen: {formatTimestamp(visitor.firstVisit)}
                    </div>
                    
                    {visitor.userAgent && (
                      <div className="text-gray-500 text-xs truncate">
                        UA: {visitor.userAgent.substring(0, 60)}...
                      </div>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  );
}

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
