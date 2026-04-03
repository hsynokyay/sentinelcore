"use client";

interface FindingFiltersBarProps {
  severity: string;
  status: string;
  findingType: string;
  onSeverityChange: (value: string) => void;
  onStatusChange: (value: string) => void;
  onTypeChange: (value: string) => void;
}

export function FindingFiltersBar({
  severity,
  status,
  findingType,
  onSeverityChange,
  onStatusChange,
  onTypeChange,
}: FindingFiltersBarProps) {
  const selectClass =
    "border rounded-md px-3 py-1.5 text-sm bg-background focus:outline-none focus:ring-2 focus:ring-ring";

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <div>
        <label className="text-xs text-muted-foreground block mb-1">Severity</label>
        <select value={severity} onChange={(e) => onSeverityChange(e.target.value)} className={selectClass}>
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
      </div>
      <div>
        <label className="text-xs text-muted-foreground block mb-1">Status</label>
        <select value={status} onChange={(e) => onStatusChange(e.target.value)} className={selectClass}>
          <option value="">All</option>
          <option value="new">New</option>
          <option value="confirmed">Confirmed</option>
          <option value="in_progress">In Progress</option>
          <option value="mitigated">Mitigated</option>
          <option value="resolved">Resolved</option>
          <option value="accepted_risk">Accepted Risk</option>
          <option value="false_positive">False Positive</option>
        </select>
      </div>
      <div>
        <label className="text-xs text-muted-foreground block mb-1">Type</label>
        <select value={findingType} onChange={(e) => onTypeChange(e.target.value)} className={selectClass}>
          <option value="">All</option>
          <option value="sast">SAST</option>
          <option value="dast">DAST</option>
          <option value="sca">SCA</option>
        </select>
      </div>
    </div>
  );
}
