import { useEffect, useRef } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Activity } from "lucide-react";
import type { PacketLog } from "@shared/schema";

interface PacketCaptureProps {
  packets: PacketLog[];
  isActive: boolean;
}

export default function PacketCapture({ packets, isActive }: PacketCaptureProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [packets]);

  const formatTimestamp = (timestamp: Date) => {
    return new Date(timestamp).toLocaleTimeString('en-US', { 
      hour12: false, 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit',
      fractionalSecondDigits: 3 
    });
  };

  const getPacketTypeClass = (protocol: string | null, payload: string | null) => {
    if (protocol === 'TCP') return 'packet-tcp';
    if (protocol === 'HTTP' || payload?.includes('HTTP')) return 'packet-http';
    if (payload?.includes('SUSPICIOUS') || payload?.includes('FAILED')) return 'packet-danger';
    return 'text-gray-400';
  };

  return (
    <Card className="bg-panel border-matrix/20">
      <CardHeader>
        <CardTitle className="font-mono text-matrix text-lg flex items-center justify-between">
          <div className="flex items-center">
            <Activity className="w-5 h-5 mr-2" />
            Live Packet Capture
          </div>
          <Badge className={`${isActive ? 'bg-matrix/20 text-matrix' : 'bg-danger/20 text-danger'} font-mono text-xs`}>
            {isActive ? 'ACTIVE' : 'INACTIVE'}
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div 
          ref={scrollRef}
          className="bg-terminal border border-matrix/30 rounded p-4 h-64 overflow-y-auto font-mono text-xs space-y-1"
        >
          {packets.length === 0 ? (
            <div className="text-gray-500 text-center py-8">
              {isActive ? 'Waiting for network traffic...' : 'Packet capture inactive'}
            </div>
          ) : (
            packets.map((packet) => (
              <div 
                key={packet.id} 
                className={`packet-log ${getPacketTypeClass(packet.protocol, packet.payload)}`}
              >
                <span className="text-gray-500">
                  {formatTimestamp(packet.timestamp!)}
                </span>
                {' '}
                <span className="text-matrix">
                  {packet.protocol}
                </span>
                {' '}
                <span>
                  {packet.sourceIp}:{packet.port} → {packet.destinationIp}
                </span>
                {packet.size && (
                  <span className="text-gray-500">
                    {' '}Len={packet.size}
                  </span>
                )}
                {packet.payload && (
                  <div className="ml-4 text-accent">
                    {packet.payload}
                  </div>
                )}
              </div>
            ))
          )}
          {isActive && (
            <div className="text-matrix opacity-70">
              {formatTimestamp(new Date())} Monitoring network traffic...
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
