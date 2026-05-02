import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { getNotifications, markRead, markAllRead, getUnreadCount } from "./api";

export function useNotifications() {
  return useQuery({
    queryKey: ["notifications"],
    queryFn: () => getNotifications(),
  });
}

export function useUnreadCount() {
  return useQuery({
    queryKey: ["notifications", "unread-count"],
    queryFn: () => getUnreadCount(),
    refetchInterval: 30000,
  });
}

export function useMarkRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => markRead(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}

export function useMarkAllRead() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => markAllRead(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["notifications"] });
    },
  });
}
