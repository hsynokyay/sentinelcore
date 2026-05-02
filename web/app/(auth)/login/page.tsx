"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { ShieldCheck } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useAuth } from "@/features/auth/hooks"

export default function LoginPage() {
  const { login, isAuthenticated } = useAuth()
  const router = useRouter()
  const [email, setEmail] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)
  const [loading, setLoading] = React.useState(false)

  React.useEffect(() => {
    if (isAuthenticated) router.push("/findings")
  }, [isAuthenticated, router])

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      await login(email, password)
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen mesh-gradient-brand mesh-animated relative overflow-hidden">
      <div className="grain-overlay" aria-hidden="true" />

      <div className="relative z-10 min-h-screen grid lg:grid-cols-[3fr_2fr]">
        {/* Hero side */}
        <aside className="hidden lg:flex relative items-center justify-center p-12">
          <div className="max-w-lg">
            <div className="flex items-center gap-3 mb-10">
              <div className="flex size-11 items-center justify-center rounded-xl bg-brand/15 ring-1 ring-brand/30">
                <ShieldCheck className="size-6 text-brand" />
              </div>
              <span className="font-display text-2xl font-semibold tracking-tight text-foreground">
                SentinelCore
              </span>
            </div>
            <h1 className="font-display text-display-2xl text-foreground mb-5">
              Application security,<br />
              <span className="bg-gradient-to-r from-brand via-[oklch(0.7_0.22_300)] to-[oklch(0.65_0.2_265)] bg-clip-text text-transparent">
                automated.
              </span>
            </h1>
            <p className="text-body text-muted-foreground max-w-md leading-relaxed">
              SAST, DAST, and risk correlation in one platform. Confirm what&apos;s exploitable.
              Mute what isn&apos;t. Ship without surprises.
            </p>

            <div className="mt-10 grid grid-cols-3 gap-4 max-w-md">
              {[
                { num: "100+", label: "SAST rules" },
                { num: "10+", label: "DAST checks" },
                { num: "RT", label: "Risk correlation" },
              ].map((s) => (
                <div key={s.label} className="rounded-lg border border-border-subtle bg-surface-1/40 backdrop-blur-sm p-3">
                  <div className="text-display font-display text-foreground">{s.num}</div>
                  <div className="text-caption text-muted-foreground mt-0.5">{s.label}</div>
                </div>
              ))}
            </div>
          </div>
        </aside>

        {/* Form side */}
        <main className="flex items-center justify-center p-6 lg:p-12">
          <div className="w-full max-w-sm">
            {/* Mobile-only header */}
            <div className="lg:hidden flex items-center gap-2.5 mb-8">
              <div className="flex size-9 items-center justify-center rounded-lg bg-brand/15 ring-1 ring-brand/30">
                <ShieldCheck className="size-5 text-brand" />
              </div>
              <span className="font-display text-h1 text-foreground">SentinelCore</span>
            </div>

            <div className="rounded-2xl glass-card border border-border p-7 glow-brand-soft">
              <div className="mb-6">
                <h2 className="font-display text-h1 text-foreground">Sign in</h2>
                <p className="text-body-sm text-muted-foreground mt-1">
                  Welcome back. Enter your credentials to continue.
                </p>
              </div>

              <form onSubmit={onSubmit} className="space-y-4">
                <div>
                  <Label htmlFor="email">Email</Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                    autoFocus
                  />
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="current-password"
                    required
                  />
                </div>
                {error && (
                  <p className="text-body-sm text-[color:var(--severity-critical)]" role="alert">{error}</p>
                )}
                <Button type="submit" size="lg" className="w-full" disabled={loading}>
                  {loading ? "Signing in…" : "Sign in"}
                </Button>
              </form>
            </div>

            <p className="mt-6 text-caption text-muted-foreground text-center tracking-wide">
              v0.1.0 · Need help? Contact your administrator.
            </p>
          </div>
        </main>
      </div>
    </div>
  )
}
