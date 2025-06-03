import {
  adminUsers,
  visitors,
  packetLogs,
  analytics,
  contentModifications,
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
} from "@shared/schema";
import { db } from "./db";
import { eq, desc, and, gte, sql, isNotNull } from "drizzle-orm";

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
}

export class DatabaseStorage implements IStorage {
  // Admin user operations
  async getAdminUser(id: number): Promise<AdminUser | undefined> {
    const [user] = await db.select().from(adminUsers).where(eq(adminUsers.id, id));
    return user || undefined;
  }

  async getAdminUserByUsername(username: string): Promise<AdminUser | undefined> {
    const [user] = await db.select().from(adminUsers).where(eq(adminUsers.username, username));
    return user || undefined;
  }

  async createAdminUser(insertUser: InsertAdminUser): Promise<AdminUser> {
    const [user] = await db
      .insert(adminUsers)
      .values(insertUser)
      .returning();
    return user;
  }

  async updateAdminLastLogin(id: number): Promise<void> {
    await db
      .update(adminUsers)
      .set({ lastLogin: new Date() })
      .where(eq(adminUsers.id, id));
  }

  // Visitor tracking operations
  async createVisitor(visitor: InsertVisitor): Promise<Visitor> {
    const [newVisitor] = await db
      .insert(visitors)
      .values(visitor)
      .returning();
    return newVisitor;
  }

  async updateVisitor(id: number, updates: Partial<InsertVisitor>): Promise<Visitor | undefined> {
    const [updatedVisitor] = await db
      .update(visitors)
      .set({ ...updates, lastSeen: new Date() })
      .where(eq(visitors.id, id))
      .returning();
    return updatedVisitor || undefined;
  }

  async getRecentVisitors(limit: number): Promise<Visitor[]> {
    return await db
      .select()
      .from(visitors)
      .orderBy(desc(visitors.lastSeen))
      .limit(limit);
  }

  async getVisitorStats(): Promise<{ total: number; unique: number; countries: number }> {
    const [totalResult] = await db
      .select({ count: sql<number>`count(*)` })
      .from(visitors);

    const [uniqueResult] = await db
      .select({ count: sql<number>`count(distinct ${visitors.ipAddress})` })
      .from(visitors);

    const [countriesResult] = await db
      .select({ count: sql<number>`count(distinct ${visitors.country})` })
      .from(visitors)
      .where(sql`${visitors.country} is not null`);

    return {
      total: totalResult?.count || 0,
      unique: uniqueResult?.count || 0,
      countries: countriesResult?.count || 0,
    };
  }

  // Packet capture operations
  async createPacketLog(log: InsertPacketLog): Promise<PacketLog> {
    const [newLog] = await db
      .insert(packetLogs)
      .values(log)
      .returning();
    return newLog;
  }

  async getRecentPacketLogs(limit: number): Promise<PacketLog[]> {
    return await db
      .select()
      .from(packetLogs)
      .orderBy(desc(packetLogs.timestamp))
      .limit(limit);
  }

  async getPacketLogsByTimeRange(startTime: Date, endTime: Date): Promise<PacketLog[]> {
    return await db
      .select()
      .from(packetLogs)
      .where(
        and(
          gte(packetLogs.timestamp, startTime),
          sql`${packetLogs.timestamp} <= ${endTime}`
        )
      )
      .orderBy(desc(packetLogs.timestamp));
  }

  // Analytics operations
  async createAnalytics(analyticsData: InsertAnalytics): Promise<Analytics> {
    const [newAnalytics] = await db
      .insert(analytics)
      .values(analyticsData)
      .returning();
    return newAnalytics;
  }

  async getAnalyticsByMetric(metric: string): Promise<Analytics[]> {
    return await db
      .select()
      .from(analytics)
      .where(eq(analytics.metric, metric))
      .orderBy(desc(analytics.timestamp));
  }

  async getLatestAnalytics(): Promise<Analytics[]> {
    return await db
      .select()
      .from(analytics)
      .orderBy(desc(analytics.timestamp))
      .limit(100);
  }

  // Content modification operations
  async createContentModification(modification: InsertContentModification): Promise<ContentModification> {
    const [newModification] = await db
      .insert(contentModifications)
      .values(modification)
      .returning();
    return newModification;
  }

  async getContentModifications(section?: string): Promise<ContentModification[]> {
    const query = db.select().from(contentModifications);

    if (section) {
      return await query
        .where(eq(contentModifications.section, section))
        .orderBy(desc(contentModifications.timestamp));
    }

    return await query.orderBy(desc(contentModifications.timestamp));
  }
  // User Management Methods
  async createAdminUser(userData: {
    username: string;
    password: string;
    role?: string;
    telegramBotToken?: string | null;
    active?: boolean;
  }) {
    const [user] = await db.insert(adminUsers).values({
      username: userData.username,
      password: userData.password,
      role: userData.role || 'operator',
      telegramBotToken: userData.telegramBotToken,
      active: userData.active !== false,
      createdAt: new Date(),
      lastLogin: null
    }).returning();
    return user;
  }

  async getAllAdminUsers() {
    return await db.select().from(adminUsers).orderBy(adminUsers.createdAt);
  }

  async updateAdminUser(userId: number, updateData: any) {
    const [user] = await db.update(adminUsers)
      .set(updateData)
      .where(eq(adminUsers.id, userId))
      .returning();
    return user;
  }

  async deleteAdminUser(userId: number) {
    await db.delete(adminUsers).where(eq(adminUsers.id, userId));
  }

  async getTelegramUsers() {
    try {
      const users = await db.select().from(adminUsers).where(eq(adminUsers.active, true));
      return users.map(user => ({
        id: user.id,
        username: user.username,
        chatId: 0, // Will be set when user starts bot
        botToken: user.telegramBotToken || '',
        role: (user.role || 'operator') as 'admin' | 'operator' | 'analyst',
        active: user.active
      }));
    } catch (error) {
      console.error('Error fetching Telegram users:', error);
      return [];
    }
  }

  async updateUserTelegramInfo(userId: number, chatId: number) {
    const [user] = await db.update(adminUsers)
      .set({ telegramChatId: chatId })
      .where(eq(adminUsers.id, userId))
      .returning();
    return user;
  }

  async createAdminUser(userData: typeof insertAdminUserSchema._type) {
    const [user] = await db.insert(adminUsers).values({
      ...userData,
      approved: userData.role === 'admin' ? true : false // Auto-approve admins
    }).returning();
    return user;
  }

  async approveUser(userId: number) {
    const [user] = await db.update(adminUsers)
      .set({ approved: true })
      .where(eq(adminUsers.id, userId))
      .returning();
    return user;
  }

  async getPendingUsers() {
    return await db.select().from(adminUsers).where(eq(adminUsers.approved, false));
  }
}

export const storage = new DatabaseStorage();