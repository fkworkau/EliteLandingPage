import { pgTable, text, serial, integer, boolean, timestamp, varchar, jsonb, index, bigint } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

// Session storage table for admin authentication
export const sessions = pgTable(
  "sessions",
  {
    sid: varchar("sid").primaryKey(),
    sess: jsonb("sess").notNull(),
    expire: timestamp("expire").notNull(),
  },
  (table) => [index("IDX_session_expire").on(table.expire)],
);

// Admin users table
export const adminUsers = pgTable("admin_users", {
  id: serial("id").primaryKey(),
  username: varchar("username", { length: 255 }).notNull().unique(),
  password: varchar("password", { length: 255 }).notNull(),
  role: varchar("role", { length: 50 }).default("operator"),
  telegramBotToken: varchar("telegram_bot_token", { length: 255 }),
  telegramChatId: bigint("telegram_chat_id", { mode: "number" }),
  telegramUserId: bigint("telegram_user_id", { mode: "number" }),
  active: boolean("active").default(true),
  approved: boolean("approved").default(false),
  createdAt: timestamp("created_at").defaultNow(),
  lastLogin: timestamp("last_login"),
});

// Visitor tracking table
export const visitors = pgTable("visitors", {
  id: serial("id").primaryKey(),
  ipAddress: text("ip_address").notNull(),
  userAgent: text("user_agent"),
  country: text("country"),
  city: text("city"),
  latitude: text("latitude"),
  longitude: text("longitude"),
  sessionId: text("session_id"),
  cookieConsent: boolean("cookie_consent"),
  firstVisit: timestamp("first_visit").defaultNow(),
  lastSeen: timestamp("last_seen").defaultNow(),
});

// Packet capture logs table
export const packetLogs = pgTable("packet_logs", {
  id: serial("id").primaryKey(),
  timestamp: timestamp("timestamp").defaultNow(),
  sourceIp: text("source_ip"),
  destinationIp: text("destination_ip"),
  protocol: text("protocol"),
  port: integer("port"),
  payload: text("payload"),
  size: integer("size"),
  isEducational: boolean("is_educational").default(true),
});

// System analytics table
export const analytics = pgTable("analytics", {
  id: serial("id").primaryKey(),
  metric: text("metric").notNull(),
  value: text("value").notNull(),
  timestamp: timestamp("timestamp").defaultNow(),
});

// AI content modifications log
export const contentModifications = pgTable("content_modifications", {
  id: serial("id").primaryKey(),
  section: text("section").notNull(),
  originalContent: text("original_content"),
  modifiedContent: text("modified_content"),
  aiModel: text("ai_model"),
  timestamp: timestamp("timestamp").defaultNow(),
  adminUserId: integer("admin_user_id").references(() => adminUsers.id),
});

// Telegram registration requests table
export const registrationRequests = pgTable("registration_requests", {
  id: serial("id").primaryKey(),
  telegramUserId: bigint("telegram_user_id", { mode: "number" }).notNull(),
  telegramUsername: varchar("telegram_username", { length: 255 }).notNull(),
  firstName: varchar("first_name", { length: 255 }),
  lastName: varchar("last_name", { length: 255 }),
  chatId: bigint("chat_id", { mode: "number" }).notNull(),
  registrationToken: varchar("registration_token", { length: 50 }).notNull(),
  telegramData: jsonb("telegram_data"),
  approved: boolean("approved").default(false),
  approvedBy: integer("approved_by").references(() => adminUsers.id),
  approvedAt: timestamp("approved_at"),
  createdAt: timestamp("created_at").defaultNow(),
});

// Schema exports
export const insertAdminUserSchema = createInsertSchema(adminUsers).pick({
  username: true,
  password: true,
});

export const insertVisitorSchema = createInsertSchema(visitors).omit({
  id: true,
  firstVisit: true,
  lastSeen: true,
});

export const insertPacketLogSchema = createInsertSchema(packetLogs).omit({
  id: true,
  timestamp: true,
});

export const insertAnalyticsSchema = createInsertSchema(analytics).omit({
  id: true,
  timestamp: true,
});

export const insertContentModificationSchema = createInsertSchema(contentModifications).omit({
  id: true,
  timestamp: true,
});

export const insertRegistrationRequestSchema = createInsertSchema(registrationRequests).omit({
  id: true,
  createdAt: true,
});

// Type exports
export type AdminUser = typeof adminUsers.$inferSelect;
export type InsertAdminUser = z.infer<typeof insertAdminUserSchema>;
export type Visitor = typeof visitors.$inferSelect;
export type InsertVisitor = z.infer<typeof insertVisitorSchema>;
export type PacketLog = typeof packetLogs.$inferSelect;
export type InsertPacketLog = z.infer<typeof insertPacketLogSchema>;
export type Analytics = typeof analytics.$inferSelect;
export type InsertAnalytics = z.infer<typeof insertAnalyticsSchema>;
export type ContentModification = typeof contentModifications.$inferSelect;
export type InsertContentModification = z.infer<typeof insertContentModificationSchema>;
export type RegistrationRequest = typeof registrationRequests.$inferSelect;
export type InsertRegistrationRequest = z.infer<typeof insertRegistrationRequestSchema>;