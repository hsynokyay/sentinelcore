"use client";

import { Download } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { exportFindingMarkdown } from "./finding-export";
import { downloadAsFile, safeFilename } from "./download";
import type { Finding } from "@/lib/types";

interface ExportFindingButtonProps {
  finding: Finding;
}

export function ExportFindingButton({ finding }: ExportFindingButtonProps) {
  const handleExport = () => {
    const md = exportFindingMarkdown(finding);
    const filename = safeFilename(finding.title, "-finding.md");
    downloadAsFile(md, filename);
    toast.success("Finding exported", {
      description: filename,
    });
  };

  return (
    <Button variant="outline" size="sm" onClick={handleExport} className="gap-1.5">
      <Download className="h-3.5 w-3.5" />
      Export
    </Button>
  );
}
