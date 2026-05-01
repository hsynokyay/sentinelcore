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
    <div className="min-h-screen grid lg:grid-cols-[3fr_2fr] bg-bg">
      <aside className="hidden lg:flex relative items-center justify-center p-10 bg-gradient-to-br from-[oklch(0.18_0.04_285)] to-[oklch(0.14_0.02_14)] overflow-hidden">
        <div className="relative z-10 max-w-md">
          <div className="flex items-center gap-2 mb-6">
            <ShieldCheck className="size-8 text-brand" />
            <span className="text-display text-foreground">SentinelCore</span>
          </div>
          <p className="text-h2 text-muted-foreground/90 leading-snug">
            Application security, automated. SAST + DAST + risk correlation in one platform.
          </p>
        </div>
      </aside>

      <main className="flex items-center justify-center p-6 lg:p-10">
        <div className="w-full max-w-sm space-y-6">
          <div className="lg:hidden flex items-center gap-2 mb-6">
            <ShieldCheck className="size-7 text-brand" />
            <span className="text-h1 text-foreground">SentinelCore</span>
          </div>

          <div>
            <h1 className="text-h1 text-foreground">Sign in</h1>
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
              <p className="text-body-sm text-[color:var(--severity-critical)]">{error}</p>
            )}
            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Signing in…" : "Sign in"}
            </Button>
          </form>

          <p className="text-caption text-muted-foreground text-center">
            v0.1.0 · Need help? Contact your administrator.
          </p>
        </div>
      </main>
    </div>
  )
}
