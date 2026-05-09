"use client";

import { PageHeader } from "@/components/data/page-header";
import { SettingsForm } from "@/features/governance/settings-form";
import { EmergencyStopSection } from "@/features/governance/emergency-stop-section";

const sections = [
  { id: "governance", label: "Governance" },
  { id: "sla", label: "SLA Policies" },
  { id: "emergency-stop", label: "Emergency Stop" },
] as const;

export default function SettingsPage() {
  return (
    <>
      <PageHeader
        title="Settings"
        description="Configure governance policies and SLA requirements"
      />
      <div className="grid gap-6 grid-cols-[200px_1fr]">
        <aside className="space-y-1">
          {sections.map((s) => (
            <a
              key={s.id}
              href={`#${s.id}`}
              className="block rounded-md px-2 py-1.5 text-body-sm text-muted-foreground hover:bg-surface-2 hover:text-foreground transition-colors duration-fast"
            >
              {s.label}
            </a>
          ))}
        </aside>
        <div className="space-y-10">
          <section id="governance">
            <SettingsForm />
          </section>
          <section id="emergency-stop">
            <EmergencyStopSection />
          </section>
        </div>
      </div>
    </>
  );
}
