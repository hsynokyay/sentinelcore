"use client";

import { useState, useCallback, useMemo, useEffect } from "react";
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
  Hash,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Play,
  RefreshCw,
  Search,
  Settings,
  Shield,
  Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useAuth } from "@/features/auth/hooks";
import { useCommandContext } from "./command-provider";

export interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

// ─── Types ──────────────────────────────────────────────────────────

interface CommandEntry {
  id: string;
  group: string;
  label: string;
  /** Optional secondary text rendered in muted to the right of the label. */
  hint?: string;
  icon: React.ComponentType<{ className?: string }>;
  onSelect: () => void;
  keywords?: string[];
}

// ─── Prefix modes ───────────────────────────────────────────────────

/**
 * Prefix modes let power users narrow the palette to a single group
 * by typing a sigil at the start of the input:
 *
 *   #  → Jump to risk (searches loaded risk titles)
 *   >  → Actions + System only
 *   @  → Pages only
 *
 * The prefix is stripped from the actual search query before cmdk's
 * fuzzy matcher runs, so "# sql" searches risk titles for "sql",
 * not for "# sql".
 */
interface PrefixMode {
  prefix: string;
  /** Which groups to show when this prefix is active. */
  groups: string[];
  /** Placeholder text shown in the input when this prefix is active. */
  placeholder: string;
}

const PREFIX_MODES: PrefixMode[] = [
  {
    prefix: "#",
    groups: ["Risks"],
    placeholder: "Jump to risk…",
  },
  {
    prefix: ">",
    groups: ["Actions", "System", "Context"],
    placeholder: "Run action…",
  },
  {
    prefix: "@",
    groups: ["Pages"],
    placeholder: "Go to page…",
  },
];

function detectPrefixMode(input: string): PrefixMode | undefined {
  for (const mode of PREFIX_MODES) {
    if (input.startsWith(mode.prefix)) return mode;
  }
  return undefined;
}

// ─── Recent commands ────────────────────────────────────────────────

const RECENT_KEY = "sentinel_recent_commands";
const MAX_RECENT = 5;

function getRecentIds(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(RECENT_KEY);
    return raw ? (JSON.parse(raw) as string[]).slice(0, MAX_RECENT) : [];
  } catch {
    return [];
  }
}

function pushRecent(id: string): void {
  if (typeof window === "undefined") return;
  try {
    const prev = getRecentIds().filter((r) => r !== id);
    localStorage.setItem(
      RECENT_KEY,
      JSON.stringify([id, ...prev].slice(0, MAX_RECENT)),
    );
  } catch {
    // localStorage full or unavailable — silently ignore.
  }
}

// ─── Group ordering ─────────────────────────────────────────────────

const GROUP_ORDER = [
  "Recent",
  "Pages",
  "Risks",
  "Context",
  "Actions",
  "System",
];

function sortGroups(
  grouped: Record<string, CommandEntry[]>,
): [string, CommandEntry[]][] {
  return Object.entries(grouped).sort(
    ([a], [b]) =>
      (GROUP_ORDER.indexOf(a) === -1 ? 99 : GROUP_ORDER.indexOf(a)) -
      (GROUP_ORDER.indexOf(b) === -1 ? 99 : GROUP_ORDER.indexOf(b)),
  );
}

// ─── Component ──────────────────────────────────────────────────────

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const router = useRouter();
  const { logout } = useAuth();
  const [search, setSearch] = useState("");

  // Reset search when palette opens/closes.
  useEffect(() => {
    if (!open) setSearch("");
  }, [open]);

  const prefixMode = detectPrefixMode(search);

  const runAndClose = useCallback(
    (id: string, action: () => void) => {
      pushRecent(id);
      action();
      onOpenChange(false);
    },
    [onOpenChange],
  );

  // ── Static commands ─────────────────────────────────────────────
  const staticCommands: CommandEntry[] = useMemo(
    () => [
      // Pages
      { id: "nav-dashboard", group: "Pages", label: "Dashboard", icon: LayoutDashboard, onSelect: () => runAndClose("nav-dashboard", () => router.push("/dashboard")), keywords: ["home", "overview"] },
      { id: "nav-findings", group: "Pages", label: "Findings", icon: Shield, onSelect: () => runAndClose("nav-findings", () => router.push("/findings")), keywords: ["vulnerabilities", "issues"] },
      { id: "nav-risks", group: "Pages", label: "Risks", icon: AlertTriangle, onSelect: () => runAndClose("nav-risks", () => router.push("/risks")), keywords: ["clusters", "correlated"] },
      { id: "nav-scans", group: "Pages", label: "Scans", icon: Play, onSelect: () => runAndClose("nav-scans", () => router.push("/scans")), keywords: ["jobs", "runs"] },
      { id: "nav-targets", group: "Pages", label: "Targets", icon: Target, onSelect: () => runAndClose("nav-targets", () => router.push("/targets")), keywords: ["scan targets", "endpoints"] },
      { id: "nav-auth-profiles", group: "Pages", label: "Auth Profiles", icon: KeyRound, onSelect: () => runAndClose("nav-auth-profiles", () => router.push("/auth-profiles")), keywords: ["credentials", "tokens"] },
      { id: "nav-artifacts", group: "Pages", label: "Source Artifacts", icon: FileArchive, onSelect: () => runAndClose("nav-artifacts", () => router.push("/artifacts")), keywords: ["uploads", "sast"] },
      { id: "nav-surface", group: "Pages", label: "Attack Surface", icon: Globe, onSelect: () => runAndClose("nav-surface", () => router.push("/surface")), keywords: ["routes", "exposure"] },
      { id: "nav-approvals", group: "Pages", label: "Approvals", icon: CheckCircle, onSelect: () => runAndClose("nav-approvals", () => router.push("/approvals")), keywords: ["governance"] },
      { id: "nav-notifications", group: "Pages", label: "Notifications", icon: Bell, onSelect: () => runAndClose("nav-notifications", () => router.push("/notifications")), keywords: ["alerts"] },
      { id: "nav-audit", group: "Pages", label: "Audit Log", icon: FileText, onSelect: () => runAndClose("nav-audit", () => router.push("/audit")), keywords: ["events", "trail"] },
      { id: "nav-settings", group: "Pages", label: "Settings", icon: Settings, onSelect: () => runAndClose("nav-settings", () => router.push("/settings")), keywords: ["configuration"] },
      // Actions
      { id: "action-logout", group: "Actions", label: "Sign out", icon: LogOut, onSelect: () => runAndClose("action-logout", () => logout()), keywords: ["logout"] },
      // System
      { id: "system-refresh", group: "System", label: "Refresh data", icon: RefreshCw, onSelect: () => runAndClose("system-refresh", () => window.location.reload()), keywords: ["reload", "cache"] },
    ],
    [runAndClose, router, logout],
  );

  // ── Dynamic commands from provider ──────────────────────────────
  const { commands: dynamicCommands } = useCommandContext();
  const dynamicEntries: CommandEntry[] = useMemo(
    () =>
      dynamicCommands.map((dc) => ({
        id: dc.id,
        group: dc.group,
        label: dc.label,
        icon: dc.icon ?? Settings,
        onSelect: () => runAndClose(dc.id, dc.onSelect),
        keywords: dc.keywords,
      })),
    [dynamicCommands, runAndClose],
  );

  // ── Merge all commands ──────────────────────────────────────────
  const allCommands = useMemo(
    () => [...staticCommands, ...dynamicEntries],
    [staticCommands, dynamicEntries],
  );

  // ── Recent commands (shown only when input is empty) ────────────
  const recentIds = useMemo(() => (open ? getRecentIds() : []), [open]);
  const recentCommands: CommandEntry[] = useMemo(() => {
    if (search.length > 0) return [];
    return recentIds
      .map((id) => allCommands.find((c) => c.id === id))
      .filter((c): c is CommandEntry => c != null)
      .map((c) => ({ ...c, id: `recent-${c.id}`, group: "Recent", hint: c.group }));
  }, [recentIds, allCommands, search]);

  // ── Grouping with prefix filtering ──────────────────────────────
  const visibleCommands = useMemo(() => {
    const base = [...recentCommands, ...allCommands];
    if (!prefixMode) return base;
    return base.filter((c) => prefixMode.groups.includes(c.group));
  }, [recentCommands, allCommands, prefixMode]);

  const grouped = useMemo(() => {
    const map: Record<string, CommandEntry[]> = {};
    for (const cmd of visibleCommands) {
      (map[cmd.group] ??= []).push(cmd);
    }
    return sortGroups(map);
  }, [visibleCommands]);

  // ── Placeholder text ────────────────────────────────────────────
  const placeholder = prefixMode
    ? prefixMode.placeholder
    : "Type a command… (# risk, > action, @ page)";

  return (
    <Command.Dialog
      open={open}
      onOpenChange={onOpenChange}
      label="Command palette"
      shouldFilter={!prefixMode}
      contentClassName={cn(
        "fixed left-1/2 top-[15vh] z-50 -translate-x-1/2",
        "w-[calc(100vw-2rem)] max-w-xl",
        "overflow-hidden rounded-xl border bg-card shadow-2xl",
        "data-[state=open]:animate-in data-[state=open]:zoom-in-95",
        "data-[state=closed]:animate-out data-[state=closed]:zoom-out-95",
      )}
      overlayClassName={cn(
        "fixed inset-0 z-40 bg-foreground/40 backdrop-blur-sm",
        "data-[state=open]:animate-in data-[state=open]:fade-in-0",
        "data-[state=closed]:animate-out data-[state=closed]:fade-out-0",
      )}
    >
      <RadixDialog.Title className="sr-only">
        Command palette
      </RadixDialog.Title>
      <RadixDialog.Description className="sr-only">
        Search for a page, risk, or action. Use # for risks, &gt; for actions, @ for pages.
      </RadixDialog.Description>

      <div className="flex items-center gap-2 border-b px-3">
        {prefixMode ? (
          <Hash aria-hidden="true" className="size-4 shrink-0 text-primary" />
        ) : (
          <Search aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
        )}
        <Command.Input
          value={search}
          onValueChange={setSearch}
          placeholder={placeholder}
          className="h-12 flex-1 bg-transparent outline-none text-sm placeholder:text-muted-foreground"
        />
        {prefixMode && (
          <span className="rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
            {prefixMode.prefix}
          </span>
        )}
        <kbd className="hidden rounded border bg-muted px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground sm:inline-block">
          Esc
        </kbd>
      </div>

      <Command.List className="max-h-[60vh] overflow-y-auto p-1">
        <Command.Empty className="py-6 text-center text-sm text-muted-foreground">
          {prefixMode
            ? `No ${prefixMode.placeholder.replace("…", "")} found.`
            : "No results found."}
        </Command.Empty>

        {grouped.map(([heading, items]) => (
          <Command.Group
            key={heading}
            heading={heading}
            className={cn(
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
                  value={
                    prefixMode
                      ? cmd.label
                      : `${cmd.label} ${cmd.keywords?.join(" ") ?? ""}`
                  }
                  onSelect={cmd.onSelect}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded-md px-2 py-2 text-sm",
                    "data-[selected=true]:bg-primary/10 data-[selected=true]:text-primary",
                  )}
                >
                  <Icon className="size-4 shrink-0" />
                  <span className="flex-1 truncate">{cmd.label}</span>
                  {cmd.hint && (
                    <span className="shrink-0 text-[10px] text-muted-foreground">
                      {cmd.hint}
                    </span>
                  )}
                </Command.Item>
              );
            })}
          </Command.Group>
        ))}
      </Command.List>
    </Command.Dialog>
  );
}
