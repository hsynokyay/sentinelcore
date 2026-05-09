"use client";

import { Bell } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { EmptyStateBranded } from "@/components/data/empty-state-branded";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { Button } from "@/components/ui/button";
import { NotificationsList } from "@/features/notifications/notifications-list";
import { useNotifications, useMarkAllRead } from "@/features/notifications/hooks";

export default function NotificationsPage() {
  const { data, isLoading, isError, refetch } = useNotifications();
  const markAll = useMarkAllRead();

  const notifications = data?.notifications ?? [];
  const hasUnread = notifications.some((n) => !n.read);
  const isEmpty = !isLoading && notifications.length === 0;

  return (
    <>
      <PageHeader
        title="Notifications"
        description="Stay updated on findings, scans, and approvals"
        count={isLoading ? "—" : notifications.length}
        actions={
          hasUnread ? (
            <Button
              variant="outline"
              size="sm"
              onClick={() => markAll.mutate()}
              disabled={markAll.isPending}
            >
              {markAll.isPending ? "Marking..." : "Mark all read"}
            </Button>
          ) : undefined
        }
      />

      {isLoading && <LoadingState rows={6} />}
      {isError && <ErrorState message="Failed to load notifications" onRetry={() => refetch()} />}
      {!isLoading && !isError && isEmpty && (
        <EmptyStateBranded
          icon={Bell}
          title="Inbox zero"
          description="You have no notifications. New alerts will appear here as scans and findings are updated."
        />
      )}
      {!isLoading && !isError && !isEmpty && (
        <NotificationsList notifications={notifications} />
      )}
    </>
  );
}
