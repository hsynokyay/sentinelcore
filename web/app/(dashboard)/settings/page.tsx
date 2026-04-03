"use client";

import { PageHeader } from "@/components/data/page-header";
import { SettingsForm } from "@/features/governance/settings-form";

export default function SettingsPage() {
  return (
    <div>
      <PageHeader
        title="Settings"
        description="Configure governance policies and SLA requirements"
      />
      <SettingsForm />
    </div>
  );
}
