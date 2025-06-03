import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Monitor, Globe, MapPin } from "lucide-react";
import type { Visitor } from "@shared/schema";

interface VisitorTrackingProps {
  visitors: Visitor[];
  isActive: boolean;
}

export default function VisitorTracking({ visitors, isActive }: VisitorTrackingProps) {
  const formatTimestamp = (timestamp: Date | null) => {
    if (!timestamp) return 'Unknown';
    return new Date(timestamp).toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit'
    });
  };

  const getStatusBadge = (visitor: Visitor) => {
    if (!visitor.lastSeen) return (
      <Badge className="bg-gray-600/20 text-gray-400 text-xs font-mono">
        UNKNOWN
      </Badge>
    );

    const lastSeen = new Date(visitor.lastSeen);
    const now = new Date();
    const timeDiff = now.getTime() - lastSeen.getTime();
    const isActiveVisitor = timeDiff < 5 * 60 * 1000; // 5 minutes

    return (
      <Badge className={`${isActiveVisitor ? 'bg-matrix/20 text-matrix' : 'bg-warning/20 text-warning'} text-xs font-mono`}>
        {isActiveVisitor ? 'ACTIVE' : 'IDLE'}
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


