import type { SourceArtifact } from "@/lib/types";

// Use the same API base + auth headers as lib/api-client.ts, but we need raw
// fetch for multipart uploads (the ApiClient wrapper stringifies JSON).
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function authHeaders(includeCSRF: boolean): Record<string, string> {
  const headers: Record<string, string> = {};
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("sentinel_access_token");
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  if (includeCSRF) {
    const csrf = getCookie("sentinel_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }
  return headers;
}

export interface UploadProgress {
  loaded: number;
  total: number;
}

export async function uploadSourceArtifact(
  projectId: string,
  file: File,
  opts?: {
    name?: string;
    description?: string;
    onProgress?: (p: UploadProgress) => void;
    signal?: AbortSignal;
  },
): Promise<SourceArtifact> {
  const form = new FormData();
  form.append("file", file, file.name);
  if (opts?.name) form.append("name", opts.name);
  if (opts?.description) form.append("description", opts.description);

  // XHR so we can surface real upload progress to the operator — fetch() has
  // no standardized upload-progress API yet.
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}/api/v1/projects/${projectId}/artifacts`);
    xhr.withCredentials = true;
    for (const [k, v] of Object.entries(authHeaders(true))) {
      xhr.setRequestHeader(k, v);
    }
    if (opts?.onProgress && xhr.upload) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable) {
          opts.onProgress!({ loaded: e.loaded, total: e.total });
        }
      };
    }
    if (opts?.signal) {
      opts.signal.addEventListener("abort", () => xhr.abort());
    }
    xhr.onerror = () => reject(new Error("upload failed"));
    xhr.onabort = () => reject(new Error("upload aborted"));
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const body = JSON.parse(xhr.responseText || "{}");
          resolve(body.source_artifact as SourceArtifact);
        } catch (e) {
          reject(e);
        }
      } else {
        try {
          const body = JSON.parse(xhr.responseText || "{}");
          reject(new Error(body.error || `HTTP ${xhr.status}`));
        } catch {
          reject(new Error(`HTTP ${xhr.status}`));
        }
      }
    };
    xhr.send(form);
  });
}

export async function listSourceArtifacts(
  projectId: string,
): Promise<SourceArtifact[]> {
  const res = await fetch(
    `${API_BASE}/api/v1/projects/${projectId}/artifacts`,
    { credentials: "include", headers: authHeaders(false) },
  );
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.json();
  return (body.source_artifacts as SourceArtifact[]) ?? [];
}

export async function deleteSourceArtifact(id: string): Promise<void> {
  const res = await fetch(`${API_BASE}/api/v1/artifacts/${id}`, {
    method: "DELETE",
    credentials: "include",
    headers: authHeaders(true),
  });
  if (!res.ok && res.status !== 204) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
}
