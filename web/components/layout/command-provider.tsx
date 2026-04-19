"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";

/**
 * A command that any page or component can register at runtime. When
 * registered, it appears in the palette alongside the static commands.
 * When the registering component unmounts, the command is automatically
 * removed via the cleanup returned by `useRegisterCommands`.
 */
export interface DynamicCommand {
  /** Unique id. Must be stable across renders — React reconciliation
   *  uses it, and duplicate ids silently shadow each other. */
  id: string;
  /** Display label in the palette list. */
  label: string;
  /** Which group the command appears in. Static commands use "Pages"
   *  and "Actions"; contextual commands typically use "Context" or a
   *  page-specific group name. The palette sorts groups in a fixed
   *  order: Pages → Context → Actions → System. */
  group: string;
  /** Callback when the command is selected. Receives no arguments —
   *  the command closure captures everything it needs. */
  onSelect: () => void;
  /** Optional Lucide icon component. */
  icon?: React.ComponentType<{ className?: string }>;
  /** Extra fuzzy-search keywords beyond the label. */
  keywords?: string[];
}

interface CommandContextValue {
  /** Currently registered dynamic commands. */
  commands: DynamicCommand[];
  /** Register one or more commands. Returns a cleanup function that
   *  removes them. Designed to be called inside `useEffect` so the
   *  commands are tied to the registering component's lifecycle. */
  register: (cmds: DynamicCommand[]) => () => void;
}

const CommandContext = createContext<CommandContextValue>({
  commands: [],
  register: () => () => undefined,
});

/**
 * CommandProvider — lives in AppShell and provides a registration
 * channel for dynamic/contextual commands. Any child component can
 * call `useRegisterCommands(cmds)` to inject commands into the
 * palette for as long as that component is mounted.
 *
 * The provider holds the command registry in state. When a component
 * registers commands, they're added to the registry; when the
 * component unmounts (or deps change), the cleanup removes them.
 * The palette reads `useCommandContext().commands` to render both
 * static and dynamic commands.
 *
 * Performance: the provider re-renders only when the registry
 * changes (commands added/removed). The palette is the only
 * consumer, and it's rendered conditionally (only when open).
 */
export function CommandProvider({ children }: { children: React.ReactNode }) {
  const [commands, setCommands] = useState<DynamicCommand[]>([]);

  const register = useCallback((cmds: DynamicCommand[]) => {
    setCommands((prev) => [...prev, ...cmds]);
    return () => {
      const ids = new Set(cmds.map((c) => c.id));
      setCommands((prev) => prev.filter((c) => !ids.has(c.id)));
    };
  }, []);

  const value = useMemo(() => ({ commands, register }), [commands, register]);

  return (
    <CommandContext.Provider value={value}>{children}</CommandContext.Provider>
  );
}

/**
 * Read the dynamic command registry. Used by CommandPalette to merge
 * dynamic commands with the static ones.
 */
export function useCommandContext(): CommandContextValue {
  return useContext(CommandContext);
}

/**
 * Register one or more contextual commands that live as long as the
 * calling component. Commands are added on mount and removed on
 * unmount (or when the serialized command ids change).
 *
 * Important: pass a **stable** array (via useMemo or a module-level
 * constant) to avoid re-registering on every render. If the commands
 * depend on component state, wrap them in useMemo with the relevant
 * deps — the hook uses the serialized ids as its effect dependency
 * so it re-registers only when the command set actually changes.
 *
 * Usage:
 *   useRegisterCommands([
 *     { id: "risk-resolve", label: "Resolve this risk", group: "Context", onSelect: () => ... },
 *   ]);
 */
export function useRegisterCommands(commands: DynamicCommand[]): void {
  const { register } = useCommandContext();

  // Memoize the commands array by serializing the ids. This ensures
  // we re-register when the set of command ids changes (e.g., risk
  // detail unmounts and a new one mounts) without re-registering on
  // every render just because the caller passes an inline array.
  const ids = commands.map((c) => c.id).join(",");
  // eslint-disable-next-line react-hooks/exhaustive-deps -- ids is the stable key
  const stable = useMemo(() => commands, [ids]);

  useEffect(() => {
    if (stable.length === 0) return undefined;
    return register(stable);
  }, [register, stable]);
}
