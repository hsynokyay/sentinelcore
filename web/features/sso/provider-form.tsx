"use client";

import { useState } from "react";
import { Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { SSOProvider } from "./types";

// Built-in roles from migration 024 (Phase 1). If the product ever adds
// a roles-list endpoint, replace this with a fetched list.
const ROLE_IDS = [
  { id: "owner", label: "Owner" },
  { id: "admin", label: "Admin" },
  { id: "security_engineer", label: "Security Engineer" },
  { id: "auditor", label: "Auditor" },
  { id: "developer", label: "Developer" },
];

const DEFAULT_SCOPES = ["openid", "email", "profile", "groups"];

export interface ProviderFormValues {
  provider_slug: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes: string[];
  default_role_id: string;
  sync_role_on_login: boolean;
  sso_logout_enabled: boolean;
  enabled: boolean;
}

export function emptyProviderForm(): ProviderFormValues {
  return {
    provider_slug: "",
    display_name: "",
    issuer_url: "",
    client_id: "",
    client_secret: "",
    scopes: DEFAULT_SCOPES,
    default_role_id: "developer",
    sync_role_on_login: true,
    sso_logout_enabled: false,
    enabled: true,
  };
}

export function providerFormFromExisting(p: SSOProvider): ProviderFormValues {
  return {
    provider_slug: p.provider_slug,
    display_name: p.display_name,
    issuer_url: p.issuer_url,
    client_id: p.client_id,
    client_secret: "", // never prefilled; empty = "preserve"
    scopes: p.scopes,
    default_role_id: p.default_role_id,
    sync_role_on_login: p.sync_role_on_login,
    sso_logout_enabled: p.sso_logout_enabled,
    enabled: p.enabled,
  };
}

interface ProviderFormProps {
  mode: "create" | "edit";
  values: ProviderFormValues;
  hasSecret?: boolean; // edit mode: whether the provider already has a secret
  submitting: boolean;
  error?: string | null;
  onChange: (patch: Partial<ProviderFormValues>) => void;
  onSubmit: () => void;
  onCancel: () => void;
}

export function ProviderForm(props: ProviderFormProps) {
  const { mode, values, hasSecret, submitting, error, onChange, onSubmit, onCancel } = props;
  const [scopesText, setScopesText] = useState(values.scopes.join(" "));
  const [secretDirty, setSecretDirty] = useState(mode === "create");

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        onChange({
          scopes: scopesText
            .split(/\s+/)
            .map((s) => s.trim())
            .filter(Boolean),
        });
        onSubmit();
      }}
      className="space-y-6 max-w-2xl"
    >
      {error && (
        <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="provider_slug">Provider slug *</Label>
          <Input
            id="provider_slug"
            value={values.provider_slug}
            onChange={(e) => onChange({ provider_slug: e.target.value })}
            disabled={mode === "edit"}
            placeholder="keycloak"
            pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
            required
          />
          <p className="text-xs text-muted-foreground">
            URL-safe identifier. Used in callback URLs. Cannot be changed later.
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="display_name">Display name *</Label>
          <Input
            id="display_name"
            value={values.display_name}
            onChange={(e) => onChange({ display_name: e.target.value })}
            placeholder="Keycloak"
            required
          />
          <p className="text-xs text-muted-foreground">
            Shown on login-page buttons.
          </p>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="issuer_url">Issuer URL *</Label>
        <Input
          id="issuer_url"
          type="url"
          value={values.issuer_url}
          onChange={(e) => onChange({ issuer_url: e.target.value })}
          placeholder="https://idp.example.com/realms/main"
          required
        />
        <p className="text-xs text-muted-foreground">
          The backend fetches <code>&lt;issuer&gt;/.well-known/openid-configuration</code>
          on first login.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-2">
          <Label htmlFor="client_id">Client ID *</Label>
          <Input
            id="client_id"
            value={values.client_id}
            onChange={(e) => onChange({ client_id: e.target.value })}
            required
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor="client_secret">
            Client secret {mode === "create" && "*"}
          </Label>
          {hasSecret && !secretDirty ? (
            <div className="flex items-center gap-2">
              <Input
                value="●●●●●●●●●●"
                disabled
                className="font-mono text-xs"
              />
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setSecretDirty(true)}
              >
                Change
              </Button>
            </div>
          ) : (
            <Input
              id="client_secret"
              type="password"
              value={values.client_secret}
              onChange={(e) => onChange({ client_secret: e.target.value })}
              placeholder="paste from IdP"
              required={mode === "create"}
              autoComplete="new-password"
            />
          )}
          <p className="text-xs text-muted-foreground">
            Encrypted at rest with AES-256-GCM. Never exposed on read.
          </p>
        </div>
      </div>

      <div className="space-y-2">
        <Label htmlFor="scopes">Scopes</Label>
        <Input
          id="scopes"
          value={scopesText}
          onChange={(e) => setScopesText(e.target.value)}
          placeholder="openid email profile groups"
        />
        <p className="text-xs text-muted-foreground">
          Space-separated. <code>openid</code>, <code>email</code>,{" "}
          <code>profile</code>, and <code>groups</code> are standard.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="default_role_id">Default role</Label>
        <Select
          value={values.default_role_id}
          onValueChange={(v) => onChange({ default_role_id: v })}
        >
          <SelectTrigger id="default_role_id">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ROLE_IDS.map((r) => (
              <SelectItem key={r.id} value={r.id}>
                {r.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <p className="text-xs text-muted-foreground">
          Used when a user's IdP groups don't match any group mapping.
        </p>
      </div>

      <div className="space-y-3 border rounded-md p-4">
        <ToggleRow
          checked={values.sync_role_on_login}
          onChange={(v) => onChange({ sync_role_on_login: v })}
          label="Sync role on each login"
          description="If a user's IdP group mapping changes, update their SentinelCore role on the next login."
        />
        <ToggleRow
          checked={values.sso_logout_enabled}
          onChange={(v) => onChange({ sso_logout_enabled: v })}
          label="Enable full SSO logout"
          description="On /logout, also redirect the user to the IdP's end_session_endpoint to terminate their IdP session."
        />
        <ToggleRow
          checked={values.enabled}
          onChange={(v) => onChange({ enabled: v })}
          label="Provider enabled"
          description="Disabled providers are hidden from the login page. Existing sessions remain valid until expiry."
        />
      </div>

      <div className="flex justify-end gap-2">
        <Button type="button" variant="outline" onClick={onCancel} disabled={submitting}>
          Cancel
        </Button>
        <Button type="submit" disabled={submitting}>
          {submitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
          {mode === "create" ? "Create provider" : "Save changes"}
        </Button>
      </div>
    </form>
  );
}

function ToggleRow(props: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  description: string;
}) {
  return (
    <label className="flex items-start gap-3 cursor-pointer">
      <input
        type="checkbox"
        checked={props.checked}
        onChange={(e) => props.onChange(e.target.checked)}
        className="mt-1"
      />
      <span className="flex-1">
        <span className="block text-sm font-medium">{props.label}</span>
        <span className="block text-xs text-muted-foreground">
          {props.description}
        </span>
      </span>
    </label>
  );
}
