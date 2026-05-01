export const routeLabels: Record<string, string> = {
  dashboard: "Dashboard",
  findings: "Findings",
  risks: "Risks",
  scans: "Scans",
  targets: "Targets",
  "auth-profiles": "Auth Profiles",
  artifacts: "Source Artifacts",
  surface: "Attack Surface",
  approvals: "Approvals",
  notifications: "Notifications",
  audit: "Audit Log",
  settings: "Settings",
}

export function labelForSegment(segment: string): string {
  if (routeLabels[segment]) return routeLabels[segment]
  // UUID-shaped segment → render as truncated id
  if (/^[0-9a-f]{8}-/i.test(segment)) return `#${segment.slice(0, 8)}`
  return segment.replace(/-/g, " ")
}
