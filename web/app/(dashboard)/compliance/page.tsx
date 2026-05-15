"use client";

// Phase-5 governance ops: compliance route.
//
// Tabs across the merged catalog browser and the mapping editor.
// Built-ins (org_id IS NULL) render read-only; tenant rows allow
// create + delete via the API gates.

import { useState } from "react";

import { PageHeader } from "@/components/data/page-header";
import { CatalogsPage } from "@/features/compliance/catalogs-page";
import { MappingsEditor } from "@/features/compliance/mappings-editor";

type Tab = "catalogs" | "mappings";

export default function CompliancePage() {
  const [tab, setTab] = useState<Tab>("catalogs");
  return (
    <div>
      <PageHeader
        title="Compliance"
        description="Browse OWASP, PCI, NIST and tenant-owned catalogs; manage CWE→control mappings"
      />

      <div className="mb-4 flex items-center gap-2 border-b">
        <button
          type="button"
          onClick={() => setTab("catalogs")}
          className={`px-3 py-2 text-sm border-b-2 transition-colors ${
            tab === "catalogs"
              ? "border-primary text-primary"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          Catalogs
        </button>
        <button
          type="button"
          onClick={() => setTab("mappings")}
          className={`px-3 py-2 text-sm border-b-2 transition-colors ${
            tab === "mappings"
              ? "border-primary text-primary"
              : "border-transparent text-muted-foreground hover:text-foreground"
          }`}
        >
          Mappings
        </button>
      </div>

      {tab === "catalogs" ? <CatalogsPage /> : <MappingsEditor />}
    </div>
  );
}
