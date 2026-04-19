import { useQuery } from "@tanstack/react-query";
import { getAuditData, getAuditEvents, type AuditFilters } from "./api";

export function useAuditData() {
  return useQuery({
    queryKey: ["audit-data"],
    queryFn: () => getAuditData(),
  });
}

export function useAuditEvents(filters: AuditFilters = {}) {
  return useQuery({
    queryKey: ["audit-events", filters],
    queryFn: () => getAuditEvents(filters),
  });
}
