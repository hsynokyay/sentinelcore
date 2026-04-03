import { useQuery } from "@tanstack/react-query";
import { getSurfaceEntries } from "./api";

export function useSurface() {
  return useQuery({
    queryKey: ["surface"],
    queryFn: () => getSurfaceEntries(),
  });
}
