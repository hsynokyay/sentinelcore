"use client";

import { useState } from "react";
import { FileText, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api-client";
import { exportScanReportMarkdown } from "./scan-report";
import { downloadAsFile, safeFilename } from "./download";
import type { Scan, Finding } from "@/lib/types";

interface ExportScanReportButtonProps {
  scan: Scan;
}

/**
 * Fetches findings for the scan on-demand and generates a Markdown report.
 * The fetch is lazy (only on click) so the scan detail page doesn't pay
 * for it unless the user wants the export.
 */
export function ExportScanReportButton({ scan }: ExportScanReportButtonProps) {
  const [loading, setLoading] = useState(false);

  const handleExport = async () => {
    setLoading(true);
    try {
      const res = await api.get<{ findings: Finding[] }>(
        `/api/v1/findings?scan_id=${scan.id}&limit=200`,
      );
      const findings = res.findings ?? [];

      // For each finding that has a rule_id, fetch detail to get remediation.
      // Only fetch first 10 to keep it fast — the rest get summary-only.
      const detailed: Finding[] = [];
      for (const f of findings.slice(0, 10)) {
        try {
          const detail = await api.get<{ finding: Finding }>(
            `/api/v1/findings/${f.id}`,
          );
          detailed.push(detail.finding);
        } catch {
          detailed.push(f);
        }
      }
      // Append the rest without detail fetch.
      for (const f of findings.slice(10)) {
        detailed.push(f);
      }

      const md = exportScanReportMarkdown({ scan, findings: detailed });
      const label = scan.project_name || scan.scan_type;
      const filename = safeFilename(`${label}-scan-report`, ".md");
      downloadAsFile(md, filename);
      toast.success("Scan report exported", { description: filename });
    } catch (err) {
      toast.error("Export failed", {
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleExport}
      disabled={loading}
      className="gap-1.5"
    >
      {loading ? (
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
      ) : (
        <FileText className="h-3.5 w-3.5" />
      )}
      {loading ? "Generating…" : "Export Report"}
    </Button>
  );
}
