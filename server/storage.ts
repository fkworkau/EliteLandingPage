import {
  adminUsers,
  visitors,
  packetLogs,
  analytics,
  contentModifications,
  registrationRequests,
  type AdminUser,
  type InsertAdminUser,
  type Visitor,
  type InsertVisitor,
  type PacketLog,
  type InsertPacketLog,
  type Analytics,
  type InsertAnalytics,
  type ContentModification,
  type InsertContentModification,
  type RegistrationRequest,
  type InsertRegistrationRequest,
} from "@shared/schema";
import { db, testConnection } from './db';
import { visitorLogs, securityEvents, analyticsEvents } from '../shared/schema';
import { eq, desc, and, gte, sql, isNotNull } from "drizzle-orm";
import bcrypt from 'bcrypt';

export interface IStorage {
  // Admin user operations
  getAdminUser(id: number): Promise<AdminUser | undefined>;
  getAdminUserByUsername(username: string): Promise<AdminUser | undefined>;
  createAdminUser(user: InsertAdminUser): Promise<AdminUser>;
  updateAdminLastLogin(id: number): Promise<void>;

  // Visitor tracking operations
  createVisitor(visitor: InsertVisitor): Promise<Visitor>;
  updateVisitor(id: number, updates: Partial<InsertVisitor>): Promise<Visitor | undefined>;
  getRecentVisitors(limit: number): Promise<Visitor[]>;
  getVisitorStats(): Promise<{ total: number; unique: number; countries: number }>;

  // Packet capture operations
  createPacketLog(log: InsertPacketLog): Promise<PacketLog>;
  getRecentPacketLogs(limit: number): Promise<PacketLog[]>;
  getPacketLogsByTimeRange(startTime: Date, endTime: Date): Promise<PacketLog[]>;

  // Analytics operations
  createAnalytics(analytics: InsertAnalytics): Promise<Analytics>;
  getAnalyticsByMetric(metric: string): Promise<Analytics[]>;
  getLatestAnalytics(): Promise<Analytics[]>;

  // Content modification operations
  createContentModification(modification: InsertContentModification): Promise<ContentModification>;
  getContentModifications(section?: string): Promise<ContentModification[]>;

  // Registration request operations
  createRegistrationRequest(request: InsertRegistrationRequest): Promise<RegistrationRequest>;
  getRegistrationRequest(id: number): Promise<RegistrationRequest | undefined>;
  getPendingRegistrations(): Promise<RegistrationRequest[]>;
  updateRegistrationRequest(id: number, updates: Partial<InsertRegistrationRequest>): Promise<RegistrationRequest | undefined>;
  getAdminUsers(): Promise<AdminUser[]>;
}

export const storage = {
  // Initialize storage and test connection
  async initialize() {
    const connected = await testConnection();
    if (!connected) {
      throw new Error('Failed to connect to database');
    }
    console.log('✅ Storage initialized successfully');
  },

  // Security event logging
  async logSecurityEvent(event: { event: string; data: string; timestamp: Date; source: string }) {
    try {
      await db.insert(securityEvents).values(event);
    } catch (error) {
      console.error('Failed to log security event:', error);
    }
  },

  // Analytics logging
  async logAnalyticsEvent(event: { metric: string; value: string; timestamp?: Date }) {
    try {
      await db.insert(analyticsEvents).values({
        ...event,
        timestamp: event.timestamp || new Date()
      });
    } catch (error) {
      console.error('Failed to log analytics event:', error);
    }
  },

  // Visitor management
  async logVisitor(visitor: { ipAddress: string; userAgent: string; country?: string; city?: string; timestamp?: Date }) {
    try {
      await db.insert(visitorLogs).values({
        ...visitor,
        timestamp: visitor.timestamp || new Date()
      });
    } catch (error) {
      console.error('Failed to log visitor:', error);
    }
  },

  async getVisitorStats() {
    try {
      const total = await db.select({ count: sql<number>`count(*)` }).from(visitorLogs);
      const unique = await db.select({ count: sql<number>`count(distinct ${visitorLogs.ipAddress})` }).from(visitorLogs);
      const countries = await db.select({ count: sql<number>`count(distinct ${visitorLogs.country})` }).from(visitorLogs);

      return {
        total: total[0]?.count || 0,
        unique: unique[0]?.count || 0,
        countries: countries[0]?.count || 0
      };
    } catch (error) {
      console.error('Failed to get visitor stats:', error);
      return { total: 0, unique: 0, countries: 0 };
    }
  },

  async getRecentVisitors(limit = 10) {
    try {
      return await db.select().from(visitorLogs).orderBy(desc(visitorLogs.timestamp)).limit(limit);
    } catch (error) {
      console.error('Failed to get recent visitors:', error);
      return [];
    }
  },

  // Packet logging
  async logPacket(packet: { sourceIp: string; destIp: string; protocol: string; port: number; data?: string; timestamp?: Date }) {
    try {
      await db.insert(packetLogs).values({
        ...packet,
        timestamp: packet.timestamp || new Date()
      });
    } catch (error) {
      console.error('Failed to log packet:', error);
    }
  },

  async getRecentPacketLogs(limit = 50) {
    try {
      return await db.select().from(packetLogs).orderBy(desc(packetLogs.timestamp)).limit(limit);
    } catch (error) {
      console.error('Failed to get packet logs:', error);
      return [];
    }
  },

  // User management
  async createAdminUser(userData: {
    username: string;
    password: string;
    role: string;
    telegramBotToken?: string;
    telegramChatId?: number;
    telegramUserId?: number;
    approved?: boolean;
    active?: boolean;
  }) {
    try {
      const hashedPassword = await bcrypt.hash(userData.password, 12);
      const [user] = await db.insert(adminUsers).values({
        ...userData,
        password: hashedPassword,
        createdAt: new Date(),
        lastLogin: new Date()
      }).returning();
      return user;
    } catch (error) {
      console.error('Failed to create admin user:', error);
      throw error;
    }
  },

  async findAdminUser(username: string) {
    try {
      const [user] = await db.select().from(adminUsers).where(eq(adminUsers.username, username));
      return user;
    } catch (error) {
      console.error('Failed to find admin user:', error);
      return null;
    }
  },

  async getAdminUsers() {
    try {
      return await db.select().from(adminUsers);
    } catch (error) {
      console.error('Failed to get admin users:', error);
      return [];
    }
  },

  async getTelegramUsers() {
    try {
      return await db.select().from(adminUsers).where(eq(adminUsers.approved, true));
    } catch (error) {
      console.error('Failed to get telegram users:', error);
      return [];
    }
  },

  async findTelegramUser(telegramUserId: number) {
    try {
      const [user] = await db.select().from(adminUsers).where(eq(adminUsers.telegramUserId, telegramUserId));
      return user;
    } catch (error) {
      console.error('Failed to find telegram user:', error);
      return null;
    }
  },

  // Registration management
  async createRegistrationRequest(data: {
    telegramUserId: number;
    telegramUsername: string;
    firstName: string;
    lastName?: string;
    chatId: number;
    registrationToken: string;
    telegramData: string;
  }) {
    try {
      const [request] = await db.insert(registrationRequests).values({
        ...data,
        createdAt: new Date()
      }).returning();
      return request;
    } catch (error) {
      console.error('Failed to create registration request:', error);
      throw error;
    }
  },

  async getRegistrationRequest(id: number) {
    try {
      const [request] = await db.select().from(registrationRequests).where(eq(registrationRequests.id, id));
      return request;
    } catch (error) {
      console.error('Failed to get registration request:', error);
      return null;
    }
  },

  async updateRegistrationRequest(id: number, data: { approved?: boolean; approvedBy?: number; approvedAt?: Date }) {
    try {
      await db.update(registrationRequests).set(data).where(eq(registrationRequests.id, id));
    } catch (error) {
      console.error('Failed to update registration request:', error);
      throw error;
    }
  }
};