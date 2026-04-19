"use client";

import Link from "next/link";
import { KeyRound, ChevronRight } from "lucide-react";
import { PageHeader } from "@/components/data/page-header";
import { SettingsForm } from "@/features/governance/settings-form";
import { EmergencyStopSection } from "@/features/governance/emergency-stop-section";

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Settings"
        description="Configure governance policies and SLA requirements"
      />
      <SettingsForm />
      <EmergencyStopSection />

      {/*
       * Link out to sub-settings pages. SSO is permission-gated at the
       * API layer (sso.manage); the link is always visible but non-
       * privileged users get a 403 response from the provider list.
       */}
      <Link
        href="/settings/sso"
        className="flex items-center justify-between p-4 border rounded-md hover:bg-muted/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <KeyRound className="h-5 w-5 text-primary" />
          <div>
            <div className="font-medium">Single Sign-On</div>
            <div className="text-xs text-muted-foreground">
              Configure OIDC providers (Azure AD, Okta, Keycloak).
            </div>
          </div>
        </div>
        <ChevronRight className="h-4 w-4 text-muted-foreground" />
      </Link>
    </div>
  );
}
