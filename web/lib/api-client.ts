// In production (via nginx reverse proxy), NEXT_PUBLIC_API_URL is empty
// string — requests go to the same origin ("/api/v1/..."), no CORS.
// In local dev, falls back to http://localhost:8080 (direct to Go backend).
const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

// Read a cookie value by name from document.cookie.
function getCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : null;
}

class ApiClient {
  private getToken(): string | null {
    if (typeof window === "undefined") return null;
    return localStorage.getItem("sentinel_access_token");
  }

  async fetch<T>(path: string, options: RequestInit = {}): Promise<T> {
    const token = this.getToken();
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options.headers as Record<string, string>),
    };
    if (token) headers["Authorization"] = `Bearer ${token}`;

    // CSRF: on state-changing requests, read the sentinel_csrf cookie
    // and send it as X-CSRF-Token header (double-submit cookie pattern).
    const method = (options.method || "GET").toUpperCase();
    if (method !== "GET" && method !== "HEAD" && method !== "OPTIONS") {
      const csrfToken = getCookie("sentinel_csrf");
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken;
      }
    }

    // Include credentials so httpOnly cookies are sent automatically.
    // This enables cookie-based auth (primary) alongside Bearer token (fallback).
    const res = await fetch(`${API_BASE}${path}`, { ...options, headers, credentials: "include" });

    if (res.status === 401) {
      localStorage.removeItem("sentinel_access_token");
      localStorage.removeItem("sentinel_refresh_token");
      if (typeof window !== "undefined") window.location.href = "/login";
      throw new Error("Unauthorized");
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: "Unknown error" }));
      throw new Error(err.error || `API error: ${res.status}`);
    }

    // 204 No Content and any empty body — safe default for DELETE-style ops.
    if (res.status === 204) return undefined as T;
    const text = await res.text();
    if (!text) return undefined as T;
    return JSON.parse(text) as T;
  }

  get<T>(path: string) {
    return this.fetch<T>(path);
  }

  post<T>(path: string, body?: unknown) {
    return this.fetch<T>(path, {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  put<T>(path: string, body: unknown) {
    return this.fetch<T>(path, {
      method: "PUT",
      body: JSON.stringify(body),
    });
  }

  patch<T>(path: string, body: unknown) {
    return this.fetch<T>(path, {
      method: "PATCH",
      body: JSON.stringify(body),
    });
  }

  delete<T>(path: string) {
    return this.fetch<T>(path, { method: "DELETE" });
  }
}

export const api = new ApiClient();
