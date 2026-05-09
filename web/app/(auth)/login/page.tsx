"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { ShieldCheck, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { useAuth } from "@/features/auth/hooks";
import { loginSchema, type LoginFormData } from "@/features/auth/schemas";
import { SSOLoginButtons } from "@/features/sso/login-buttons";

// Derive the org slug from an email's domain: alice@acme.com → "acme".
// Returns undefined when the email is malformed or still being typed.
function deriveOrgSlug(email: string): string | undefined {
  const at = email.indexOf("@");
  if (at < 0) return undefined;
  const host = email.slice(at + 1).split(".")[0];
  return host ? host.toLowerCase() : undefined;
}

export default function LoginPage() {
  const { login } = useAuth();
  const [error, setError] = useState<string | null>(null);

  const { register, handleSubmit, watch, formState: { errors, isSubmitting } } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
  });
  const emailValue = watch("email") ?? "";
  const orgSlug = deriveOrgSlug(emailValue);

  const onSubmit = async (data: LoginFormData) => {
    setError(null);
    try {
      await login(data.email, data.password);
    } catch (err) {
      // SSO-only users surface as "use SSO to sign in" from the backend
      // (HTTP 401, code=USE_SSO). Nudge the user toward the SSO buttons
      // which are already visible below.
      const msg = err instanceof Error ? err.message : "Login failed";
      if (msg.toLowerCase().includes("use sso")) {
        setError("Your account uses SSO — use the provider button below.");
      } else {
        setError(msg);
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-muted/30">
      <Card className="w-full max-w-sm">
        <CardHeader className="text-center">
          <div className="mx-auto mb-2">
            <ShieldCheck className="h-10 w-10 text-primary" />
          </div>
          <CardTitle className="text-xl">SentinelCore</CardTitle>
          <CardDescription>Sign in to your account</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            {error && (
              <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">{error}</div>
            )}
            <div className="space-y-2">
              <Label htmlFor="email">Email</Label>
              <Input id="email" type="email" placeholder="admin@example.com" {...register("email")} />
              {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
            </div>
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input id="password" type="password" {...register("password")} />
              {errors.password && <p className="text-xs text-destructive">{errors.password.message}</p>}
            </div>
            <Button type="submit" className="w-full" disabled={isSubmitting}>
              {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Sign in
            </Button>
          </form>
          {/*
           * SSO buttons render only when orgSlug is derivable AND at least
           * one enabled provider exists for that org (the hook fails closed
           * to an empty list — unknown orgs render nothing).
           */}
          <SSOLoginButtons orgSlug={orgSlug} />
        </CardContent>
      </Card>
    </div>
  );
}
