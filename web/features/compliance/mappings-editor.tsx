"use client";

// Phase-5 governance ops: compliance mappings editor.
//
// Single-screen editor for the merged built-in + tenant CWE→control
// mapping set. Built-in mappings (org_id IS NULL) render as read-only;
// tenant mappings get a delete button. New tenant mappings can be added
// via the inline form.

import { useMemo, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { LoadingState } from "@/components/data/loading-state";
import { ErrorState } from "@/components/data/error-state";
import { EmptyState } from "@/components/data/empty-state";

import {
  useComplianceCatalogs,
  useComplianceMappings,
  useCreateMapping,
  useDeleteMapping,
} from "./hooks";
import type { ComplianceCatalog, ComplianceItem, ComplianceMapping } from "@/lib/types";
import { listCatalogItems } from "./api";

interface ItemMap {
  [itemID: string]: { catalog: ComplianceCatalog; item: ComplianceItem };
}

export function MappingsEditor() {
  const catalogs = useComplianceCatalogs();
  const [filterCWE, setFilterCWE] = useState("");

  const filterCode = filterCWE.trim()
    ? filterCWE.startsWith("CWE-")
      ? filterCWE
      : `CWE-${filterCWE}`
    : "";

  const mappings = useComplianceMappings(
    filterCode ? { source_kind: "cwe", source_code: filterCode } : {},
  );

  // Resolve item id → (catalog, item) for nice rendering. We lazy-load
  // each catalog's items the first time it shows up in the mapping
  // table; results live in component state.
  const [itemMap, setItemMap] = useState<ItemMap>({});
  const catalogsByID = useMemo(() => {
    const m: Record<string, ComplianceCatalog> = {};
    (catalogs.data ?? []).forEach((c) => (m[c.id] = c));
    return m;
  }, [catalogs.data]);

  // Resolve missing item ids on each render of the mappings list.
  const missingCatalogIDs = useMemo(() => {
    if (!mappings.data) return [] as string[];
    const need = new Set<string>();
    for (const m of mappings.data) {
      if (!itemMap[m.target_control_id]) {
        // We do not know which catalog owns the item up-front, so we
        // load every visible catalog's items once.
        for (const c of catalogs.data ?? []) need.add(c.id);
      }
    }
    return Array.from(need);
  }, [mappings.data, itemMap, catalogs.data]);

  // Eagerly fetch items for every visible catalog the first time we see
  // an unresolved mapping. Cheap for the seeded set (~50 items per cat).
  if (missingCatalogIDs.length > 0 && Object.keys(itemMap).length === 0) {
    Promise.all(
      missingCatalogIDs.map((cid) =>
        listCatalogItems(cid).then((items) => ({ cid, items })),
      ),
    ).then((results) => {
      const next: ItemMap = {};
      for (const { cid, items } of results) {
        const cat = catalogsByID[cid];
        if (!cat) continue;
        for (const it of items) next[it.id] = { catalog: cat, item: it };
      }
      setItemMap(next);
    });
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Filter</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-3">
            <div className="flex-1">
              <Label htmlFor="cwe-filter">CWE</Label>
              <Input
                id="cwe-filter"
                value={filterCWE}
                onChange={(e) => setFilterCWE(e.target.value)}
                placeholder="79 or CWE-79 (leave empty for all)"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Mappings</CardTitle>
        </CardHeader>
        <CardContent>
          {mappings.isLoading ? <LoadingState /> : null}
          {mappings.isError ? (
            <ErrorState message="Failed to load mappings" onRetry={() => mappings.refetch()} />
          ) : null}
          {mappings.data && mappings.data.length === 0 ? (
            <EmptyState
              title="No mappings"
              description={filterCode ? `No mappings for ${filterCode}.` : "No mappings exist."}
            />
          ) : null}
          {mappings.data && mappings.data.length > 0 ? (
            <MappingsTable mappings={mappings.data} itemMap={itemMap} />
          ) : null}
        </CardContent>
      </Card>

      <NewMappingForm
        catalogs={catalogs.data ?? []}
        itemMap={itemMap}
        ensureItemsLoaded={(cid) => {
          if (Object.values(itemMap).some(({ catalog }) => catalog.id === cid)) return;
          listCatalogItems(cid).then((items) => {
            const cat = catalogsByID[cid];
            if (!cat) return;
            setItemMap((prev) => {
              const next = { ...prev };
              for (const it of items) next[it.id] = { catalog: cat, item: it };
              return next;
            });
          });
        }}
      />
    </div>
  );
}

function MappingsTable({
  mappings,
  itemMap,
}: {
  mappings: ComplianceMapping[];
  itemMap: ItemMap;
}) {
  const del = useDeleteMapping();
  return (
    <table className="w-full text-sm">
      <thead className="text-left text-xs text-muted-foreground border-b">
        <tr>
          <th className="py-2 pr-3 font-medium">Source</th>
          <th className="py-2 pr-3 font-medium">Catalog</th>
          <th className="py-2 pr-3 font-medium">Control</th>
          <th className="py-2 pr-3 font-medium">Confidence</th>
          <th className="py-2 pr-3 font-medium">Origin</th>
          <th className="py-2 font-medium" />
        </tr>
      </thead>
      <tbody>
        {mappings.map((m) => {
          const target = itemMap[m.target_control_id];
          const isCustom = !!m.org_id;
          return (
            <tr key={m.id} className="border-b">
              <td className="py-2 pr-3 font-mono text-xs">{m.source_code}</td>
              <td className="py-2 pr-3">{target?.catalog.name ?? "—"}</td>
              <td className="py-2 pr-3 font-mono text-xs">
                {target ? `${target.item.control_id} — ${target.item.title}` : m.target_control_id}
              </td>
              <td className="py-2 pr-3">
                <Badge variant={m.confidence === "custom" ? "status" : "tag"}>
                  {m.confidence}
                </Badge>
              </td>
              <td className="py-2 pr-3">
                {isCustom ? <Badge>tenant</Badge> : <Badge variant="tag">built-in</Badge>}
              </td>
              <td className="py-2">
                {isCustom ? (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => del.mutate(m.id)}
                    disabled={del.isPending}
                  >
                    Delete
                  </Button>
                ) : null}
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

interface NewMappingFormProps {
  catalogs: ComplianceCatalog[];
  itemMap: ItemMap;
  ensureItemsLoaded: (catalogID: string) => void;
}

function NewMappingForm({ catalogs, itemMap, ensureItemsLoaded }: NewMappingFormProps) {
  const create = useCreateMapping();
  const [sourceCode, setSourceCode] = useState("");
  const [catalogID, setCatalogID] = useState("");
  const [itemID, setItemID] = useState("");
  const [error, setError] = useState<string | null>(null);

  const itemsForCatalog = useMemo(
    () =>
      Object.values(itemMap)
        .filter(({ catalog }) => catalog.id === catalogID)
        .map(({ item }) => item)
        .sort((a, b) => a.control_id.localeCompare(b.control_id)),
    [itemMap, catalogID],
  );

  const onSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const code = sourceCode.startsWith("CWE-") ? sourceCode : `CWE-${sourceCode}`;
    create.mutate(
      { source_kind: "cwe", source_code: code, target_control_id: itemID },
      {
        onSuccess: () => {
          setSourceCode("");
          setItemID("");
        },
        onError: (err: unknown) => {
          setError(err instanceof Error ? err.message : "Failed to create mapping");
        },
      },
    );
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">New tenant mapping</CardTitle>
      </CardHeader>
      <CardContent>
        <form onSubmit={onSubmit} className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <Label htmlFor="src">CWE</Label>
            <Input
              id="src"
              value={sourceCode}
              onChange={(e) => setSourceCode(e.target.value)}
              placeholder="79 or CWE-79"
              required
            />
          </div>
          <div>
            <Label htmlFor="cat">Target catalog</Label>
            <select
              id="cat"
              className="w-full h-9 px-3 rounded-md border bg-background text-sm"
              value={catalogID}
              onChange={(e) => {
                setCatalogID(e.target.value);
                setItemID("");
                if (e.target.value) ensureItemsLoaded(e.target.value);
              }}
              required
            >
              <option value="">Select catalog…</option>
              {catalogs.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name} v{c.version}
                </option>
              ))}
            </select>
          </div>
          <div>
            <Label htmlFor="item">Control item</Label>
            <select
              id="item"
              className="w-full h-9 px-3 rounded-md border bg-background text-sm"
              value={itemID}
              onChange={(e) => setItemID(e.target.value)}
              required
              disabled={!catalogID}
            >
              <option value="">Select control…</option>
              {itemsForCatalog.map((it) => (
                <option key={it.id} value={it.id}>
                  {it.control_id} — {it.title}
                </option>
              ))}
            </select>
          </div>
          {error ? <p className="text-xs text-red-600 md:col-span-3">{error}</p> : null}
          <div className="md:col-span-3">
            <Button type="submit" disabled={create.isPending || !sourceCode || !itemID}>
              {create.isPending ? "Saving…" : "Add mapping"}
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}
