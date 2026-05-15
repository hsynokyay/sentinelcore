"use client"

import * as React from "react"
import { useProjects } from "@/features/scans/hooks"
import type { Project } from "@/lib/types"

interface WorkspaceContextValue {
  projects: Project[]
  projectId: string
  setProjectId: (id: string) => void
  activeProject: Project | undefined
  isLoading: boolean
}

const WorkspaceContext = React.createContext<WorkspaceContextValue | null>(null)

const STORAGE_KEY = "sentinel_active_project_id"

export function WorkspaceProvider({ children }: { children: React.ReactNode }) {
  const { data, isLoading } = useProjects()
  const projects = React.useMemo(() => data?.projects ?? [], [data])

  const [explicit, setExplicit] = React.useState<string>(() => {
    if (typeof window === "undefined") return ""
    return localStorage.getItem(STORAGE_KEY) ?? ""
  })

  // Validate persisted ID still exists in the project list; fall back to first.
  const projectId = React.useMemo(() => {
    if (explicit && projects.some((p) => p.id === explicit)) return explicit
    return projects[0]?.id ?? ""
  }, [explicit, projects])

  const setProjectId = React.useCallback((id: string) => {
    setExplicit(id)
    if (typeof window !== "undefined") localStorage.setItem(STORAGE_KEY, id)
  }, [])

  const activeProject = React.useMemo(
    () => projects.find((p) => p.id === projectId),
    [projects, projectId]
  )

  const value = React.useMemo<WorkspaceContextValue>(
    () => ({ projects, projectId, setProjectId, activeProject, isLoading }),
    [projects, projectId, setProjectId, activeProject, isLoading]
  )

  return <WorkspaceContext.Provider value={value}>{children}</WorkspaceContext.Provider>
}

export function useWorkspace() {
  const ctx = React.useContext(WorkspaceContext)
  if (!ctx) throw new Error("useWorkspace must be used inside <WorkspaceProvider>")
  return ctx
}

export function useProjectId() {
  return useWorkspace().projectId
}
