# SSO frontend module

All files in this module are **additive** — no existing `web/` files are
modified in the Phase 3 branch. The integration edits below must be
applied at reconcile time onto whatever state of `web/` the deploy branch
carries.

## Files added

```
web/features/sso/
  api.ts              # REST calls (listSSOProviders, createSSOMapping, ...)
  hooks.ts            # TanStack Query hooks (useSSOProviders, ...)
  types.ts            # Wire types
  provider-form.tsx   # Create/edit form component
  mappings-editor.tsx # Group → role editor (inline on edit page)
  login-buttons.tsx   # "Sign in with X" buttons for the login page

web/app/(dashboard)/settings/sso/
  page.tsx            # Provider list + delete dialog
  new/page.tsx        # Create
  [id]/page.tsx       # Edit + mappings inline
```

## Integration patches (apply at reconcile)

### 1. Login page (`web/app/(auth)/login/page.tsx`)

Add the SSO-buttons section beneath the existing email/password form and
handle the `USE_SSO` error code.

**Imports** (top of file):

```tsx
import { SSOLoginButtons } from "@/features/sso/login-buttons";
```

**State** (inside the component):

```tsx
const [email, setEmail] = useState("");
const [ssoHint, setSsoHint] = useState<string[] | null>(null);
```

**Email input change handler** — replace the `register("email")` spread
with a controlled input so we can derive `orgSlug` from the domain:

```tsx
<Input
  id="email"
  type="email"
  value={email}
  onChange={(e) => setEmail(e.target.value)}
  placeholder="alice@acme.com"
/>
```

**Submit handler** — on 401 with `code === "USE_SSO"`, stash the
provider slugs so the UI can highlight which button to use:

```tsx
try {
  await login(email, data.password);
} catch (err: any) {
  const msg = err?.message ?? "Login failed";
  // The api-client rejects on 401 but swallows the body. If the
  // `credentials: include` + fetch error path carries the body through,
  // USE_SSO detection goes here:
  if (msg.includes("use SSO")) {
    setSsoHint([]); // populated once `providers` is wired through
  }
  setError(msg);
}
```

**Button section** — add at the end of the form:

```tsx
<SSOLoginButtons
  orgSlug={deriveOrgSlug(email)}
  returnTo={typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("return_to") ?? undefined : undefined}
/>
```

**Helper** (near the bottom of the file):

```tsx
function deriveOrgSlug(email: string): string | undefined {
  // Strip the domain suffix: alice@acme.com → "acme".
  // For production deployments that use a URL query param instead,
  // prefer `new URLSearchParams(window.location.search).get("org")`.
  const at = email.indexOf("@");
  if (at < 0) return undefined;
  const host = email.slice(at + 1).split(".")[0];
  return host ? host.toLowerCase() : undefined;
}
```

### 2. Settings navigation

Wherever the settings sidebar / tab list is declared (typically
`web/features/governance/settings-form.tsx` or a settings layout file),
add a link to `/settings/sso`:

```tsx
{
  href: "/settings/sso",
  label: "Single Sign-On",
  perm: "sso.manage",
}
```

Gate visibility on the `sso.manage` permission — a user without it
should not see the link.

### 3. Permission gating on the pages themselves

The Phase 1 RBAC surface exposes a `<Can perm="sso.manage">` wrapper (or
an equivalent hook). Wrap the three SSO settings pages so non-privileged
users see the standard 403 layout rather than a broken page:

```tsx
<Can perm="sso.manage" fallback={<Forbidden />}>
  {/* existing page body */}
</Can>
```

The backend RequirePermission middleware already enforces this server-side
— the wrapper is purely for UX. All API calls would 403 otherwise.

### 4. Logout flow (optional — only for SSO-enabled orgs)

If the current user signed in via SSO and the provider has
`sso_logout_enabled = true`, the local logout button should call
`ssoLogout(providerId)` (from `@/features/sso/api`) and, if the response
contains a `redirect` URL, `window.location.replace(redirect)` to
complete RP-Initiated Logout at the IdP.

```tsx
import { ssoLogout } from "@/features/sso/api";

async function onLogout() {
  const res = await ssoLogout(currentProviderId);
  if (res.redirect) {
    window.location.replace(res.redirect);
  } else {
    router.push("/login");
  }
}
```

`currentProviderId` comes from whichever session-metadata endpoint the
backend exposes (e.g. `/api/v1/users/me` once it returns `sso_provider_id`
on SSO-authenticated sessions — follow-up server change).
