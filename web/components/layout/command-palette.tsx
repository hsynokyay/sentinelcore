"use client";

import { useRouter } from "next/navigation";
import { Command } from "cmdk";
import * as RadixDialog from "@radix-ui/react-dialog";
import {
  AlertTriangle,
  Bell,
  CheckCircle,
  FileArchive,
  FileText,
  Globe,
  KeyRound,
  LogOut,
  Play,
  Search,
  Settings,
  Shield,
  Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/features/auth/hooks";

export interface CommandPaletteProps {
  /** Controlled open state. */
  open: boolean;
  /** Open-state setter — called on Esc, backdrop click, and after a
   *  command runs. */
  onOpenChange: (open: boolean) => void;
}

/**
 * One command entry in the palette. The list below is the canonical
 * SentinelCore command set — adding a new command means adding a new
 * row here, nothing else.
 *
 * Each entry pairs an icon, a label, an optional group heading, an
 * `onSelect` callback (closure over `router` and `logout`), and an
 * optional `keywords` array that cmdk uses for fuzzy-search matching
 * (so a user can type "log" to find "Sign out", or "boards" to find
 * "Approvals").
 */
interface CommandEntry {
  id: string;
  group: "Pages" | "Actions";
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  onSelect: () => void;
  /** Extra fuzzy-search keywords beyond the label. */
  keywords?: string[];
}

/**
 * CommandPalette — the global Cmd+K / Ctrl+K modal that lets users
 * jump anywhere in SentinelCore without using the sidebar.
 *
 * Built on cmdk (Paco Coursey's command palette library) for the
 * input handling, fuzzy-matching, ARIA, and keyboard navigation.
 * The styling is hand-applied Tailwind that matches the rest of the
 * security surface — same border, same card background, same focus
 * treatment for the active item.
 *
 * Layout:
 *   ┌──────────────────────────────────────────────┐
 *   │ [search icon] Type a command or search…      │
 *   ├──────────────────────────────────────────────┤
 *   │ Pages                                         │
 *   │   [icon] Findings                             │
 *   │   [icon] Risks                                │
 *   │   …                                           │
 *   │ Actions                                       │
 *   │   [icon] Sign out                             │
 *   └──────────────────────────────────────────────┘
 *
 * Pages section mirrors the sidebar one-for-one — same labels, same
 * icons, same href targets — so the palette is effectively a
 * keyboard-driven sidebar. Actions section is reserved for verbs
 * (Sign out, Refresh, etc.) and is intentionally short to avoid
 * collapsing the page list.
 */
export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const router = useRouter();
  const { logout } = useAuth();

  // Close-on-action helper. Every command runs the action and closes
  // the palette in the same gesture, so the user lands on the new
  // page (or in a logged-out state) without an extra click.
  const runAndClose = (action: () => void) => {
    action();
    onOpenChange(false);
  };

  // Page commands: derived from the sidebar nav. The icons match the
  // sidebar so users build muscle memory across the two surfaces.
  // The order is the sidebar order, which is the operator's natural
  // top-to-bottom flow (findings first, scans next, etc.).
  const commands: CommandEntry[] = [
    {
      id: "nav-findings",
      group: "Pages",
      label: "Findings",
      icon: Shield,
      onSelect: () => runAndClose(() => router.push("/findings")),
      keywords: ["vulnerabilities", "issues"],
    },
    {
      id: "nav-risks",
      group: "Pages",
      label: "Risks",
      icon: AlertTriangle,
      onSelect: () => runAndClose(() => router.push("/risks")),
      keywords: ["clusters", "correlated"],
    },
    {
      id: "nav-scans",
      group: "Pages",
      label: "Scans",
      icon: Play,
      onSelect: () => runAndClose(() => router.push("/scans")),
      keywords: ["jobs", "runs"],
    },
    {
      id: "nav-targets",
      group: "Pages",
      label: "Targets",
      icon: Target,
      onSelect: () => runAndClose(() => router.push("/targets")),
      keywords: ["scan targets", "endpoints"],
    },
    {
      id: "nav-auth-profiles",
      group: "Pages",
      label: "Auth Profiles",
      icon: KeyRound,
      onSelect: () => runAndClose(() => router.push("/auth-profiles")),
      keywords: ["credentials", "tokens"],
    },
    {
      id: "nav-artifacts",
      group: "Pages",
      label: "Source Artifacts",
      icon: FileArchive,
      onSelect: () => runAndClose(() => router.push("/artifacts")),
      keywords: ["uploads", "sast", "code"],
    },
    {
      id: "nav-surface",
      group: "Pages",
      label: "Attack Surface",
      icon: Globe,
      onSelect: () => runAndClose(() => router.push("/surface")),
      keywords: ["routes", "endpoints", "exposure"],
    },
    {
      id: "nav-approvals",
      group: "Pages",
      label: "Approvals",
      icon: CheckCircle,
      onSelect: () => runAndClose(() => router.push("/approvals")),
      keywords: ["governance", "review"],
    },
    {
      id: "nav-notifications",
      group: "Pages",
      label: "Notifications",
      icon: Bell,
      onSelect: () => runAndClose(() => router.push("/notifications")),
      keywords: ["alerts"],
    },
    {
      id: "nav-audit",
      group: "Pages",
      label: "Audit Log",
      icon: FileText,
      onSelect: () => runAndClose(() => router.push("/audit")),
      keywords: ["events", "trail"],
    },
    {
      id: "nav-settings",
      group: "Pages",
      label: "Settings",
      icon: Settings,
      onSelect: () => runAndClose(() => router.push("/settings")),
      keywords: ["configuration", "preferences"],
    },
    {
      id: "action-logout",
      group: "Actions",
      label: "Sign out",
      icon: LogOut,
      onSelect: () => runAndClose(() => logout()),
      keywords: ["logout", "log out"],
    },
  ];

  // Group commands by their declared group, preserving the original
  // order within each group. Object iteration order in modern JS
  // engines is insertion order for string keys, so this naturally
  // renders Pages before Actions.
  const grouped = commands.reduce<Record<string, CommandEntry[]>>(
    (acc, cmd) => {
      (acc[cmd.group] ??= []).push(cmd);
      return acc;
    },
    {},
  );

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Command palette"
      // cmdk's Command.Dialog has three className slots, each landing
      // on a different layer of the underlying Radix Dialog tree:
      //
      //   1. `className`         → the inner <Command> div, which
      //                            sits *inside* Dialog.Content. We
      //                            apply only the inner-card chrome here.
      //   2. `contentClassName`  → Radix Dialog.Content, the floating
      //                            modal box. This is where we put
      //                            positioning + sizing.
      //   3. `overlayClassName`  → Radix Dialog.Overlay, the backdrop.
      //
      // The earlier draft put `fixed inset-0 flex justify-center` on
      // `className`, which was applied to the inner Command — Dialog.
      // Content stayed at its default position (top-left of the
      // viewport) and the modal landed at x=0. The fix is to move
      // the positioning to contentClassName where Dialog.Content
      // can actually act on it.
      contentClassName={cn(
        // Positioning: pinned at the top with a top offset, horizontally
        // centered via left-1/2 + translate-x. `w-[calc(100vw-2rem)]`
        // gives a small inset on narrow viewports; `max-w-xl` caps it
        // at 576px on wider screens.
        "fixed left-1/2 top-[15vh] z-50 -translate-x-1/2",
        "w-[calc(100vw-2rem)] max-w-xl",
        // Visual chrome — same border / card / shadow vocabulary as
        // the rest of the security surface.
        "overflow-hidden rounded-xl border bg-card shadow-2xl",
        // Mount/unmount animation gated by Radix's data-state.
        "data-[state=open]:animate-in data-[state=open]:zoom-in-95",
        "data-[state=closed]:animate-out data-[state=closed]:zoom-out-95",
      )}
      // Default backdrop is transparent — give it a subtle blur and
      // a faint dark wash so the modal feels lifted off the page
      // without yelling.
      overlayClassName={cn(
        "fixed inset-0 z-40 bg-foreground/40 backdrop-blur-sm",
        "data-[state=open]:animate-in data-[state=open]:fade-in-0",
        "data-[state=closed]:animate-out data-[state=closed]:fade-out-0",
      )}
    >
      {/* Radix Dialog requires a DialogTitle for screen readers.
          cmdk's Command.Dialog wraps Radix internally but doesn't
          expose a title slot, so we inject one as a visually hidden
          element. sr-only keeps it out of the visual layout while
          screen readers announce "Command palette" when the dialog
          opens. */}
      {/* Radix Dialog a11y: title (screen-reader only) + description
          suppression. cmdk wraps Radix Dialog internally but doesn't
          expose title/description slots, so we inject them here. */}
      <RadixDialog.Title className="sr-only">
        Command palette
      </RadixDialog.Title>
      <RadixDialog.Description className="sr-only">
        Search for a page or action, then press Enter to run it.
      </RadixDialog.Description>

      <div className="flex items-center gap-2 border-b px-3">
        <Search aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
        <Command.Input
          placeholder="Type a command or search…"
          className="h-12 flex-1 bg-transparent outline-none text-sm placeholder:text-muted-foreground"
        />
        <kbd className="hidden rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground sm:inline-block">
          Esc
        </kbd>
      </div>

      <Command.List className="max-h-[60vh] overflow-y-auto p-1">
        <Command.Empty className="py-6 text-center text-sm text-muted-foreground">
          No results found.
        </Command.Empty>

        {Object.entries(grouped).map(([heading, items]) => (
          <Command.Group
            key={heading}
            heading={heading}
            className={cn(
              // The heading itself — uppercase eyebrow that matches
              // the eyebrow style we use across the security surface
              // (NextBestAction, ChangeSummaryStrip).
              "[&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5",
              "[&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-semibold",
              "[&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-widest",
              "[&_[cmdk-group-heading]]:text-muted-foreground",
            )}
          >
            {items.map((cmd) => {
              const Icon = cmd.icon;
              return (
                <Command.Item
                  key={cmd.id}
                  value={`${cmd.label} ${cmd.keywords?.join(" ") ?? ""}`}
                  onSelect={cmd.onSelect}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm",
                    // The selected item is the one cmdk's keyboard
                    // navigation is currently on. Highlight it with
                    // the same accent treatment the sidebar uses for
                    // the active route, so the two surfaces feel like
                    // one navigation system.
                    "data-[selected=true]:bg-primary/10 data-[selected=true]:text-primary",
                  )}
                >
                  <Icon className="size-4 shrink-0" />
                  <span>{cmd.label}</span>
                </Command.Item>
              );
            })}
          </Command.Group>
        ))}
      </Command.List>
    </Command.Dialog>
  );
}
