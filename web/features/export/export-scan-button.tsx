"use client";

import { FileText } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { exportScanReportMarkdown, type ScanReportData } from "./scan-report";
import { downloadAsFile, safeFilename } from "./download";

interface ExportScanButtonProps {
  data: ScanReportData;
}

export function ExportScanButton({ data }: ExportScanButtonProps) {
  const handleExport = () => {
    const md = exportScanReportMarkdown(data);
    const label = data.scan.project_name || data.scan.scan_type;
    const filename = safeFilename(`${label}-scan-report`, ".md");
    downloadAsFile(md, filename);
    toast.success("Scan report exported", {
      description: filename,
    });
  };

  return (
    <Button variant="outline" size="sm" onClick={handleExport} className="gap-1.5">
      <FileText className="h-3.5 w-3.5" />
      Export Report
    </Button>
  );
}
