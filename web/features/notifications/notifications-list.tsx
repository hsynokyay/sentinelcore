"use client";

import { useMarkRead } from "./hooks";
import type { Notification } from "@/lib/types";

const categoryColors: Record<string, string> = {
  finding: "bg-red-500",
  scan: "bg-blue-500",
  approval: "bg-yellow-500",
  system: "bg-gray-500",
};

function formatRelativeDate(dateStr: string): string {
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);
  if (diffMins < 1) return "just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

interface NotificationsListProps {
  notifications: Notification[];
}

export function NotificationsList({ notifications }: NotificationsListProps) {
  const markReadMut = useMarkRead();

  if (notifications.length === 0) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <p className="text-sm">No notifications</p>
      </div>
    );
  }

  return (
    <div className="divide-y">
      {notifications.map((n) => (
        <div
          key={n.id}
          className={`flex items-start gap-3 px-4 py-3 transition-colors ${
            !n.read ? "bg-muted/30 hover:bg-muted/50" : "hover:bg-muted/20"
          }`}
          role="button"
          tabIndex={0}
          onClick={() => {
            if (!n.read) markReadMut.mutate(n.id);
          }}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !n.read) markReadMut.mutate(n.id);
          }}
        >
          {/* Unread dot */}
          <div className="pt-1.5 flex-shrink-0">
            {!n.read ? (
              <div className="h-2 w-2 rounded-full bg-primary" />
            ) : (
              <div className="h-2 w-2" />
            )}
          </div>

          {/* Category indicator */}
          <div className="pt-1.5 flex-shrink-0">
            <div
              className={`h-2 w-2 rounded-full ${categoryColors[n.category] || categoryColors.system}`}
            />
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground uppercase font-medium">
                {n.category}
              </span>
              <span className="text-xs text-muted-foreground">
                {formatRelativeDate(n.created_at)}
              </span>
            </div>
            <p className="text-sm font-medium text-foreground mt-0.5">{n.title}</p>
            {n.body && (
              <p className="text-sm text-muted-foreground mt-0.5 line-clamp-2">{n.body}</p>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
