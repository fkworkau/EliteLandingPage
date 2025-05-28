import { useState, useEffect } from "react";
import { io, Socket } from "socket.io-client";
import type { Visitor, PacketLog } from "@shared/schema";

export function useRealTimeData() {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [visitors, setVisitors] = useState<Visitor[]>([]);
  const [packets, setPackets] = useState<PacketLog[]>([]);

  useEffect(() => {
    const newSocket = io();
    setSocket(newSocket);

    newSocket.on('connect', () => {
      setIsConnected(true);
      console.log('Connected to real-time monitoring');
    });

    newSocket.on('disconnect', () => {
      setIsConnected(false);
      console.log('Disconnected from real-time monitoring');
    });

    newSocket.on('newVisitor', (visitor: Visitor) => {
      setVisitors(prev => [visitor, ...prev.slice(0, 49)]); // Keep last 50
    });

    newSocket.on('newPacket', (packet: PacketLog) => {
      setPackets(prev => [packet, ...prev.slice(0, 99)]); // Keep last 100
    });

    return () => {
      newSocket.close();
    };
  }, []);

  const joinAdminRoom = (token: string) => {
    if (socket) {
      socket.emit('joinAdmin', token);
    }
  };

  return {
    socket,
    isConnected,
    visitors,
    packets,
    joinAdminRoom,
  };
}
