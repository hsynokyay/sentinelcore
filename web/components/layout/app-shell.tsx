"use client";

import { useEffect, useState } from "react";
import { Sidebar } from "./sidebar";
import { Header } from "./header";
import { CommandPalette } from "./command-palette";

/**
 * AppShell — the dashboard layout root. Wraps every authenticated
 * route in the sidebar + header + main-content frame and owns the
 * global command-palette state.
 *
 * The command palette lives here (rather than in `Header` or in a
 * context provider) because:
 *  1. It's a *global* surface — every dashboard route should be
 *     able to open it via Cmd+K.
 *  2. The state is trivially small (one boolean), so context overhead
 *     would be unjustified.
 *  3. AppShell already wraps Header, so the open-state setter can be
 *     passed to Header as a regular prop for the discoverability hint.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Global Cmd+K / Ctrl+K listener. Toggles the palette open or
  // closed. Bound on `keydown` (not `keypress`) so it fires before
  // any text-input handlers consume the event, and `preventDefault`
  // is called so the browser's default Cmd+K doesn't pop the URL bar.
  //
  // Listener lifetime is tied to AppShell mount/unmount — i.e. the
  // entire authenticated session — so it never accumulates listeners.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const isModK =
        e.key.toLowerCase() === "k" && (e.metaKey || e.ctrlKey);
      if (!isModK) return;
      e.preventDefault();
      setPaletteOpen((prev) => !prev);
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header onOpenCommandPalette={() => setPaletteOpen(true)} />
        <main className="flex-1 overflow-y-auto p-6 bg-background">
          {children}
        </main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
