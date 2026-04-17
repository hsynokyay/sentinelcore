"use client";

import { Button } from "@/components/ui/button";
import { KeyRound } from "lucide-react";
import { useEnabledSSOProviders } from "./hooks";

interface SSOLoginButtonsProps {
  /**
   * The organization slug to look up providers for. In most deployments
   * this is derived from the email domain after the user types their
   * email (e.g. `alice@acme.com` → `acme`). Pass undefined to hide the
   * section until a slug is available.
   */
  orgSlug?: string;
  /**
   * Optional return_to path (same-origin, starts with `/`). The backend
   * validates this so a malicious value is silently replaced with
   * `/dashboard` — we still guard here to avoid sending obviously bad
   * values in the URL.
   */
  returnTo?: string;
}

/**
 * Renders "Sign in with <Provider>" buttons for the given org. Each
 * button is a plain anchor redirect: no client-side handling of
 * tokens, no Bearer header. The backend completes the OIDC handshake
 * and sets the session cookie on its 302 back to return_to.
 */
export function SSOLoginButtons({ orgSlug, returnTo }: SSOLoginButtonsProps) {
  const { data: providers, isLoading } = useEnabledSSOProviders(orgSlug);

  if (!orgSlug || isLoading || !providers || providers.length === 0) {
    return null;
  }

  const rt = returnTo && returnTo.startsWith("/") ? returnTo : undefined;

  return (
    <div className="space-y-2">
      <div className="relative my-4">
        <div className="absolute inset-0 flex items-center">
          <span className="w-full border-t" />
        </div>
        <div className="relative flex justify-center text-xs uppercase">
          <span className="bg-background px-2 text-muted-foreground">Or continue with</span>
        </div>
      </div>
      {providers.map((p) => {
        const url =
          p.start_url + (rt ? `?return_to=${encodeURIComponent(rt)}` : "");
        return (
          <Button
            key={p.provider_slug}
            asChild
            variant="outline"
            className="w-full"
          >
            <a href={url}>
              <KeyRound className="mr-2 h-4 w-4" />
              Sign in with {p.display_name}
            </a>
          </Button>
        );
      })}
    </div>
  );
}
