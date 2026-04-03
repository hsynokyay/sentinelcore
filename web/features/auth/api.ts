import { api } from "@/lib/api-client";
import type { TokenResponse, User } from "@/lib/types";

export async function login(
  email: string,
  password: string
): Promise<TokenResponse> {
  return api.post<TokenResponse>("/api/v1/auth/login", { email, password });
}

export async function refreshToken(
  refreshToken: string
): Promise<{ access_token: string; expires_in: number }> {
  return api.post("/api/v1/auth/refresh", { refresh_token: refreshToken });
}

export async function logout(): Promise<void> {
  await api.post("/api/v1/auth/logout");
}

export async function getCurrentUser(): Promise<User> {
  return api.get<User>("/api/v1/users/me");
}
