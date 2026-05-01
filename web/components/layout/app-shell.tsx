"use client"

import { useEffect, useState } from "react"
import { Sidebar } from "./sidebar"
import { Header } from "./header"
import { CommandPalette } from "./command-palette"
import { CommandProvider } from "./command-provider"
import { WorkspaceProvider } from "@/lib/workspace-context"
import { DensityProvider } from "@/lib/density-context"

export function AppShell({ children }: { children: React.ReactNode }) {
  const [paletteOpen, setPaletteOpen] = useState(false)

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isModK = e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey)
      if (!isModK) return
      e.preventDefault()
      setPaletteOpen((prev) => !prev)
    }
    window.addEventListener("keydown", handler)
    return () => window.removeEventListener("keydown", handler)
  }, [])

  return (
    <WorkspaceProvider>
      <DensityProvider>
        <CommandProvider>
          <div className="flex h-screen overflow-hidden bg-bg">
            <Sidebar />
            <div className="flex-1 flex flex-col overflow-hidden">
              <Header onOpenCommandPalette={() => setPaletteOpen(true)} />
              <main className="flex-1 overflow-y-auto">
                <div className="mx-auto max-w-[1440px] px-6 py-5">
                  {children}
                </div>
              </main>
            </div>
            <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
          </div>
        </CommandProvider>
      </DensityProvider>
    </WorkspaceProvider>
  )
}
