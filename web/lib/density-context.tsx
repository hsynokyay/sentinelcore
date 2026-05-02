"use client"

import * as React from "react"

type Density = "comfortable" | "compact"

interface DensityContextValue {
  density: Density
  setDensity: (d: Density) => void
}

const DensityContext = React.createContext<DensityContextValue | null>(null)
const STORAGE_KEY = "sentinel_density"

export function DensityProvider({ children }: { children: React.ReactNode }) {
  const [density, setDensityState] = React.useState<Density>(() => {
    if (typeof window === "undefined") return "comfortable"
    return (localStorage.getItem(STORAGE_KEY) as Density) ?? "comfortable"
  })

  const setDensity = React.useCallback((d: Density) => {
    setDensityState(d)
    if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, d)
  }, [])

  const value = React.useMemo(() => ({ density, setDensity }), [density, setDensity])
  return <DensityContext.Provider value={value}>{children}</DensityContext.Provider>
}

export function useDensity() {
  const ctx = React.useContext(DensityContext)
  if (!ctx) throw new Error("useDensity must be used inside <DensityProvider>")
  return ctx
}
