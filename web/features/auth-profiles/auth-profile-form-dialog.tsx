"use client";

import { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";

import {
  useCreateAuthProfile,
  useUpdateAuthProfile,
} from "./hooks";
import type {
  AuthProfile,
  AuthProfileType,
  CreateAuthProfilePayload,
} from "@/lib/types";

interface AuthProfileFormDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  projectId: string;
  existing?: AuthProfile;
}

// Secret fields are write-only: the dialog never prefills them when editing,
// and leaving them blank on save preserves the existing encrypted value.
// A secret is only rotated when the operator explicitly types a new value.
export function AuthProfileFormDialog({
  open,
  onOpenChange,
  projectId,
  existing,
}: AuthProfileFormDialogProps) {
  const isEdit = !!existing;

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [authType, setAuthType] = useState<AuthProfileType>("bearer_token");

  // bearer_token
  const [token, setToken] = useState("");
  const [tokenPrefix, setTokenPrefix] = useState("Bearer");
  // api_key
  const [apiKey, setApiKey] = useState("");
  const [headerName, setHeaderName] = useState("X-API-Key");
  // basic_auth
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [endpointUrl, setEndpointUrl] = useState("");

  const [rotating, setRotating] = useState(!isEdit); // create-mode is always "rotating"
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setError(null);
    setName(existing?.name ?? "");
    setDescription(existing?.description ?? "");
    setAuthType((existing?.auth_type as AuthProfileType) ?? "bearer_token");
    setToken("");
    setApiKey("");
    setPassword("");
    setTokenPrefix(
      (existing?.metadata?.token_prefix as string) ?? "Bearer",
    );
    setHeaderName(
      (existing?.metadata?.header_name as string) ?? "X-API-Key",
    );
    setUsername((existing?.metadata?.username as string) ?? "");
    setEndpointUrl((existing?.metadata?.endpoint_url as string) ?? "");
    setRotating(!isEdit);
  }, [open, existing, isEdit]);

  const createMut = useCreateAuthProfile(projectId);
  const updateMut = useUpdateAuthProfile(projectId);
  const isPending = createMut.isPending || updateMut.isPending;

  const submit = () => {
    setError(null);
    if (!name.trim()) {
      setError("Name is required");
      return;
    }

    const payload: CreateAuthProfilePayload = {
      name: name.trim(),
      auth_type: authType,
    };
    if (description) payload.description = description;
    if (endpointUrl) payload.endpoint_url = endpointUrl;

    // Always send metadata fields (header name, token prefix, username).
    // Only send secret fields if we're creating OR explicitly rotating.
    const shouldSendSecret = !isEdit || rotating;

    if (authType === "bearer_token") {
      payload.token_prefix = tokenPrefix || "Bearer";
      if (shouldSendSecret) {
        if (!token) {
          setError("Token is required");
          return;
        }
        payload.token = token;
      }
    } else if (authType === "api_key") {
      payload.header_name = headerName || "X-API-Key";
      if (shouldSendSecret) {
        if (!apiKey) {
          setError("API key is required");
          return;
        }
        payload.api_key = apiKey;
      }
    } else if (authType === "basic_auth") {
      if (!username) {
        setError("Username is required");
        return;
      }
      payload.username = username;
      if (shouldSendSecret) {
        if (!password) {
          setError("Password is required");
          return;
        }
        payload.password = password;
      }
    }

    const onError = (err: unknown) => {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg);
      toast.error(isEdit ? "Update failed" : "Create failed", {
        description: msg,
      });
    };

    if (isEdit && existing) {
      updateMut.mutate(
        { id: existing.id, payload },
        {
          onSuccess: () => {
            toast.success(
              rotating
                ? "Auth profile updated (secret rotated)"
                : "Auth profile updated",
            );
            onOpenChange(false);
          },
          onError,
        },
      );
    } else {
      createMut.mutate(payload, {
        onSuccess: () => {
          toast.success("Auth profile created");
          onOpenChange(false);
        },
        onError,
      });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {isEdit ? "Edit Auth Profile" : "New Auth Profile"}
          </DialogTitle>
          <DialogDescription>
            DAST credentials for authenticated scans. Secrets are stored
            encrypted at rest and never returned by the API — leave secret
            fields blank to preserve the existing value when editing.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>Name</Label>
            <Input
              placeholder="prod-api-bearer"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label>Auth Type</Label>
            <Select
              value={authType}
              onValueChange={(v) => setAuthType(v as AuthProfileType)}
              disabled={isEdit}
              itemToStringLabel={(v) => {
                if (v === "bearer_token") return "Bearer Token";
                if (v === "api_key") return "API Key";
                if (v === "basic_auth") return "Basic Auth";
                return String(v);
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select auth type" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="bearer_token">Bearer Token</SelectItem>
                <SelectItem value="api_key">API Key</SelectItem>
                <SelectItem value="basic_auth">Basic Auth</SelectItem>
              </SelectContent>
            </Select>
            {isEdit && (
              <p className="text-xs text-muted-foreground">
                Auth type is immutable after creation.
              </p>
            )}
          </div>

          {/* Type-specific fields */}
          {authType === "bearer_token" && (
            <>
              <div className="space-y-1.5">
                <Label>Header Prefix</Label>
                <Input
                  value={tokenPrefix}
                  onChange={(e) => setTokenPrefix(e.target.value)}
                  placeholder="Bearer"
                />
              </div>
              <SecretField
                label="Token"
                placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6I…"
                value={token}
                onChange={setToken}
                isEdit={isEdit}
                rotating={rotating}
                setRotating={setRotating}
                hasCredentials={!!existing?.has_credentials}
              />
            </>
          )}

          {authType === "api_key" && (
            <>
              <div className="space-y-1.5">
                <Label>Header Name</Label>
                <Input
                  value={headerName}
                  onChange={(e) => setHeaderName(e.target.value)}
                  placeholder="X-API-Key"
                />
              </div>
              <SecretField
                label="API Key"
                placeholder="sk-live-…"
                value={apiKey}
                onChange={setApiKey}
                isEdit={isEdit}
                rotating={rotating}
                setRotating={setRotating}
                hasCredentials={!!existing?.has_credentials}
              />
            </>
          )}

          {authType === "basic_auth" && (
            <>
              <div className="space-y-1.5">
                <Label>Username</Label>
                <Input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <SecretField
                label="Password"
                placeholder="••••••••"
                value={password}
                onChange={setPassword}
                isEdit={isEdit}
                rotating={rotating}
                setRotating={setRotating}
                hasCredentials={!!existing?.has_credentials}
              />
            </>
          )}

          <div className="space-y-1.5">
            <Label>
              Login / Token Endpoint URL{" "}
              <span className="text-muted-foreground font-normal">
                (optional)
              </span>
            </Label>
            <Input
              placeholder="https://api.example.com/oauth/token"
              value={endpointUrl}
              onChange={(e) => setEndpointUrl(e.target.value)}
            />
          </div>

          <div className="space-y-1.5">
            <Label>
              Description{" "}
              <span className="text-muted-foreground font-normal">
                (optional)
              </span>
            </Label>
            <Textarea
              rows={2}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          {error && (
            <p className="text-sm text-destructive">{error}</p>
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button disabled={isPending} onClick={submit}>
            {isPending && <Loader2 className="h-4 w-4 animate-spin mr-1" />}
            {isEdit ? "Save" : "Create Profile"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface SecretFieldProps {
  label: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  isEdit: boolean;
  rotating: boolean;
  setRotating: (v: boolean) => void;
  hasCredentials: boolean;
}

function SecretField({
  label,
  placeholder,
  value,
  onChange,
  isEdit,
  rotating,
  setRotating,
  hasCredentials,
}: SecretFieldProps) {
  if (isEdit && !rotating) {
    return (
      <div className="space-y-1.5">
        <Label>{label}</Label>
        <div className="flex items-center gap-2">
          <div className="flex-1 px-3 py-1.5 text-sm text-muted-foreground bg-muted rounded-md border">
            {hasCredentials ? "•••••••• (stored)" : "(none)"}
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setRotating(true)}
          >
            Rotate
          </Button>
        </div>
        <p className="text-xs text-muted-foreground">
          The stored secret is never returned. Click Rotate to replace it.
        </p>
      </div>
    );
  }
  return (
    <div className="space-y-1.5">
      <Label>{label}</Label>
      <Input
        type="password"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete="off"
      />
      {isEdit && (
        <button
          type="button"
          className="text-xs text-muted-foreground hover:text-foreground underline"
          onClick={() => {
            setRotating(false);
            onChange("");
          }}
        >
          Cancel rotation
        </button>
      )}
    </div>
  );
}
