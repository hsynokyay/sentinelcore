import { useQuery } from "@tanstack/react-query";
import { getAuditData } from "./api";

export function useAuditData() {
  return useQuery({
    queryKey: ["audit"],
    queryFn: () => getAuditData(),
  });
}
