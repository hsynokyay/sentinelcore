// Types for the SSO admin surface + login-page button component.
// Mirror of the Go structs in pkg/sso + internal/controlplane/api/sso_providers.go.

export interface SSOProvider {
  id: string;
  provider_slug: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  scopes: string[];
  default_role_id: string;
  sync_role_on_login: boolean;
  sso_logout_enabled: boolean;
  end_session_url?: string;
  enabled: boolean;
  has_secret: boolean;
}

export interface SSOProviderCreatePayload {
  provider_slug: string;
  display_name: string;
  issuer_url: string;
  client_id: string;
  client_secret: string;
  scopes?: string[];
  default_role_id: string;
  sync_role_on_login: boolean;
  sso_logout_enabled: boolean;
  enabled: boolean;
}

export interface SSOProviderUpdatePayload {
  display_name?: string;
  issuer_url?: string;
  client_id?: string;
  client_secret?: string; // empty string → preserve existing
  scopes?: string[];
  default_role_id?: string;
  sync_role_on_login: boolean;
  sso_logout_enabled: boolean;
  enabled: boolean;
}

export interface SSOGroupMapping {
  id: string;
  group_claim: string;
  role_id: string;
  priority: number;
}

export interface SSOGroupMappingPayload {
  group_claim: string;
  role_id: string;
  priority: number;
}

// Public (pre-auth) provider descriptor used by the login page.
export interface SSOEnabledProvider {
  provider_slug: string;
  display_name: string;
  start_url: string;
}
