import { pgTable, serial, varchar, timestamp, integer, text, boolean, json } from 'drizzle-orm/pg-core';

export const visitorLogs = pgTable('visitor_logs', {
  id: serial('id').primaryKey(),
  ipAddress: varchar('ip_address', { length: 45 }).notNull(),
  userAgent: text('user_agent'),
  country: varchar('country', { length: 100 }),
  city: varchar('city', { length: 100 }),
  timestamp: timestamp('timestamp').defaultNow().notNull()
});

export const packetLogs = pgTable('packet_logs', {
  id: serial('id').primaryKey(),
  sourceIp: varchar('source_ip', { length: 45 }).notNull(),
  destIp: varchar('dest_ip', { length: 45 }).notNull(),
  protocol: varchar('protocol', { length: 20 }).notNull(),
  port: integer('port').notNull(),
  data: text('data'),
  timestamp: timestamp('timestamp').defaultNow().notNull()
});

export const adminUsers = pgTable('admin_users', {
  id: serial('id').primaryKey(),
  username: varchar('username', { length: 100 }).unique().notNull(),
  password: varchar('password', { length: 255 }).notNull(),
  role: varchar('role', { length: 50 }).default('operator').notNull(),
  telegramBotToken: varchar('telegram_bot_token', { length: 255 }),
  telegramChatId: integer('telegram_chat_id'),
  telegramUserId: integer('telegram_user_id'),
  approved: boolean('approved').default(false),
  active: boolean('active').default(true),
  createdAt: timestamp('created_at').defaultNow().notNull(),
  lastLogin: timestamp('last_login')
});

export const registrationRequests = pgTable('registration_requests', {
  id: serial('id').primaryKey(),
  telegramUserId: integer('telegram_user_id').notNull(),
  telegramUsername: varchar('telegram_username', { length: 100 }),
  firstName: varchar('first_name', { length: 100 }),
  lastName: varchar('last_name', { length: 100 }),
  chatId: integer('chat_id').notNull(),
  registrationToken: varchar('registration_token', { length: 50 }).notNull(),
  telegramData: text('telegram_data'),
  approved: boolean('approved').default(false),
  approvedBy: integer('approved_by'),
  approvedAt: timestamp('approved_at'),
  createdAt: timestamp('created_at').defaultNow().notNull()
});

export const securityEvents = pgTable('security_events', {
  id: serial('id').primaryKey(),
  event: varchar('event', { length: 100 }).notNull(),
  data: text('data'),
  timestamp: timestamp('timestamp').defaultNow().notNull(),
  source: varchar('source', { length: 50 }).notNull()
});

export const analyticsEvents = pgTable('analytics_events', {
  id: serial('id').primaryKey(),
  metric: varchar('metric', { length: 100 }).notNull(),
  value: text('value'),
  timestamp: timestamp('timestamp').defaultNow().notNull()
});

import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
import { bigint, index, jsonb } from "drizzle-orm/pg-core";

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

// Schema exports
export const insertAdminUserSchema = createInsertSchema(adminUsers).pick({
  username: true,
  password: true,
});

export const insertVisitorSchema = createInsertSchema(visitorLogs).omit({
  id: true,
  timestamp: true,
});

export const insertPacketLogSchema = createInsertSchema(packetLogs).omit({
  id: true,
  timestamp: true,
});

export const insertAnalyticsSchema = createInsertSchema(analyticsEvents).omit({
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
export type Visitor = typeof visitorLogs.$inferSelect;
export type InsertVisitor = z.infer<typeof insertVisitorSchema>;
export type PacketLog = typeof packetLogs.$inferSelect;
export type InsertPacketLog = z.infer<typeof insertPacketLogSchema>;
export type Analytics = typeof analyticsEvents.$inferSelect;
export type InsertAnalytics = z.infer<typeof insertAnalyticsSchema>;
export type ContentModification = typeof contentModifications.$inferSelect;
export type InsertContentModification = z.infer<typeof insertContentModificationSchema>;
export type RegistrationRequest = typeof registrationRequests.$inferSelect;
export type InsertRegistrationRequest = z.infer<typeof insertRegistrationRequestSchema>;