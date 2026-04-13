"use client";

import { useState } from "react";
import { Code2, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api-client";
import { exportFindingSarif, exportScanSarif } from "./sarif";
import { downloadAsFile, safeFilename } from "./download";
import type { Finding, Scan } from "@/lib/types";

// --- Single finding SARIF export ---

interface ExportFindingSarifButtonProps {
  finding: Finding;
}

export function ExportFindingSarifButton({
  finding,
}: ExportFindingSarifButtonProps) {
  const handleExport = () => {
    const sarif = exportFindingSarif(finding);
    const filename = safeFilename(finding.title, ".sarif");
    downloadAsFile(sarif, filename, "application/json");
    toast.success("SARIF exported", { description: filename });
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleExport}
      className="gap-1.5"
    >
      <Code2 className="h-3.5 w-3.5" />
      SARIF
    </Button>
  );
}

// --- Scan-level SARIF export ---

interface ExportScanSarifButtonProps {
  scan: Scan;
}

export function ExportScanSarifButton({ scan }: ExportScanSarifButtonProps) {
  const [loading, setLoading] = useState(false);

  const handleExport = async () => {
    setLoading(true);
    try {
      // Fetch findings for this scan.
      const listRes = await api.get<{ findings: Finding[] }>(
        `/api/v1/findings?scan_id=${scan.id}&limit=200`,
      );
      const findings = listRes.findings ?? [];

      // Enrich first 20 with remediation detail.
      const enriched: Finding[] = [];
      for (const f of findings.slice(0, 20)) {
        try {
          const detail = await api.get<{ finding: Finding }>(
            `/api/v1/findings/${f.id}`,
          );
          enriched.push(detail.finding);
        } catch {
          enriched.push(f);
        }
      }
      for (const f of findings.slice(20)) {
        enriched.push(f);
      }

      const sarif = exportScanSarif(scan, enriched);
      const label = scan.project_name || scan.scan_type;
      const filename = safeFilename(`${label}-scan`, ".sarif");
      downloadAsFile(sarif, filename, "application/json");
      toast.success("SARIF exported", { description: filename });
    } catch (err) {
      toast.error("SARIF export failed", {
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
        <Code2 className="h-3.5 w-3.5" />
      )}
      {loading ? "Generating…" : "SARIF"}
    </Button>
  );
}
