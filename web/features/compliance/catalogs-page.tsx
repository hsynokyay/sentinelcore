"use client";

// Phase-5 governance ops: compliance catalogs browser.
//
// Master/detail layout: left side lists every catalog visible to the
// caller (built-ins + tenant-owned); right side shows the selected
// catalog's control items. Built-in catalogs are read-only; tenant
// catalogs admit a "New Item" inline form for security_admin and up.

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { EmptyState } from "@/components/data/empty-state";

import {
  useComplianceCatalogItems,
  useComplianceCatalogs,
  useCreateCatalog,
  useCreateCatalogItem,
} from "./hooks";
import type { ComplianceCatalog } from "@/lib/types";

export function CatalogsPage() {
  const catalogs = useComplianceCatalogs();
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = catalogs.data?.find((c) => c.id === selectedId) ?? catalogs.data?.[0] ?? null;

  if (catalogs.isLoading) return <LoadingState />;
  if (catalogs.isError) return <ErrorState message="Failed to load catalogs" onRetry={() => catalogs.refetch()} />;
  if (!catalogs.data || catalogs.data.length === 0) {
    return <EmptyState title="No catalogs" description="Built-in catalogs ship with SentinelCore — re-run migrations 024 and 025." />;
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div className="lg:col-span-1 space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Catalogs</CardTitle>
          </CardHeader>
          <CardContent className="space-y-1">
            {catalogs.data.map((c) => (
              <button
                key={c.id}
                type="button"
                onClick={() => setSelectedId(c.id)}
                className={`w-full text-left px-3 py-2 rounded text-sm flex items-center gap-2 ${
                  (selected?.id ?? "") === c.id
                    ? "bg-muted text-foreground"
                    : "hover:bg-muted/50 text-muted-foreground"
                }`}
              >
                <span className="flex-1">
                  <div className="font-medium text-foreground">{c.name}</div>
                  <div className="text-xs text-muted-foreground">
                    {c.code} · v{c.version}
                  </div>
                </span>
                {c.is_builtin ? (
                  <Badge variant="tag">built-in</Badge>
                ) : (
                  <Badge>custom</Badge>
                )}
              </button>
            ))}
          </CardContent>
        </Card>
        <NewCatalogForm />
      </div>

      <div className="lg:col-span-2 space-y-4">
        {selected ? <CatalogDetail catalog={selected} /> : null}
      </div>
    </div>
  );
}

function CatalogDetail({ catalog }: { catalog: ComplianceCatalog }) {
  const items = useComplianceCatalogItems(catalog.id);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base flex items-center justify-between">
          <span>
            {catalog.name}{" "}
            <span className="text-muted-foreground font-normal">v{catalog.version}</span>
          </span>
          {catalog.is_builtin ? (
            <Badge variant="tag">built-in</Badge>
          ) : (
            <Badge>custom</Badge>
          )}
        </CardTitle>
        {catalog.description ? (
          <p className="text-sm text-muted-foreground mt-1">{catalog.description}</p>
        ) : null}
      </CardHeader>
      <CardContent>
        {items.isLoading ? <LoadingState /> : null}
        {items.isError ? (
          <ErrorState message="Failed to load items" onRetry={() => items.refetch()} />
        ) : null}
        {items.data && items.data.length === 0 ? (
          <EmptyState title="No items" description="This catalog has no control items yet." />
        ) : null}
        {items.data && items.data.length > 0 ? (
          <table className="w-full text-sm">
            <thead className="text-left text-xs text-muted-foreground border-b">
              <tr>
                <th className="py-2 pr-3 font-medium">Control</th>
                <th className="py-2 pr-3 font-medium">Title</th>
                <th className="py-2 font-medium">Description</th>
              </tr>
            </thead>
            <tbody>
              {items.data.map((it) => (
                <tr key={it.id} className="border-b">
                  <td className="py-2 pr-3 font-mono text-xs">{it.control_id}</td>
                  <td className="py-2 pr-3 font-medium">{it.title}</td>
                  <td className="py-2 text-muted-foreground">{it.description ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        {!catalog.is_builtin ? <NewItemForm catalogId={catalog.id} /> : null}
      </CardContent>
    </Card>
  );
}

function NewCatalogForm() {
  const create = useCreateCatalog();
  const [code, setCode] = useState("");
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    create.mutate(
      { code, name, version, description: description || undefined },
      {
        onSuccess: () => {
          setCode("");
          setName("");
          setVersion("");
          setDescription("");
        },
        onError: (err: unknown) => {
          setError(err instanceof Error ? err.message : "Failed to create catalog");
        },
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">New custom catalog</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="space-y-3">
          <div>
            <Label htmlFor="cat-code">Code</Label>
            <Input id="cat-code" value={code} onChange={(e) => setCode(e.target.value)} placeholder="INTERNAL_SEC" required />
          </div>
          <div>
            <Label htmlFor="cat-name">Name</Label>
            <Input id="cat-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Internal Security Controls" required />
          </div>
          <div>
            <Label htmlFor="cat-version">Version</Label>
            <Input id="cat-version" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.0" required />
          </div>
          <div>
            <Label htmlFor="cat-desc">Description</Label>
            <Textarea id="cat-desc" value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
          </div>
          {error ? <p className="text-xs text-red-600">{error}</p> : null}
          <Button type="submit" disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create catalog"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function NewItemForm({ catalogId }: { catalogId: string }) {
  const create = useCreateCatalogItem(catalogId);
  const [controlID, setControlID] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [error, setError] = useState<string | null>(null);

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    create.mutate(
      { control_id: controlID, title, description: description || undefined },
      {
        onSuccess: () => {
          setControlID("");
          setTitle("");
          setDescription("");
        },
        onError: (err: unknown) => {
          setError(err instanceof Error ? err.message : "Failed to create item");
        },
      },
    );
  };

  return (
    <form onSubmit={onSubmit} className="mt-4 pt-4 border-t space-y-3">
      <h4 className="text-sm font-medium">Add item</h4>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label htmlFor="item-id">Control ID</Label>
          <Input id="item-id" value={controlID} onChange={(e) => setControlID(e.target.value)} placeholder="SEC-007" required />
        </div>
        <div>
          <Label htmlFor="item-title">Title</Label>
          <Input id="item-title" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Secure output encoding" required />
        </div>
      </div>
      <div>
        <Label htmlFor="item-desc">Description</Label>
        <Textarea id="item-desc" value={description} onChange={(e) => setDescription(e.target.value)} rows={2} />
      </div>
      {error ? <p className="text-xs text-red-600">{error}</p> : null}
      <Button type="submit" size="sm" disabled={create.isPending}>
        {create.isPending ? "Adding…" : "Add item"}
      </Button>
    </form>
  );
}
