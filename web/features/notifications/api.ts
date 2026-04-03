import { api } from "@/lib/api-client";
import type { Notification } from "@/lib/types";

export interface NotificationsResponse {
  notifications: Notification[];
}

export async function getNotifications(): Promise<NotificationsResponse> {
  return api.get<NotificationsResponse>("/api/v1/notifications");
}

export async function markRead(id: string): Promise<void> {
  await api.patch(`/api/v1/notifications/${id}/read`, {});
}

export async function markAllRead(): Promise<void> {
  await api.post("/api/v1/notifications/read-all");
}

export async function getUnreadCount(): Promise<{ count: number }> {
  return api.get<{ count: number }>("/api/v1/notifications/unread-count");
}
