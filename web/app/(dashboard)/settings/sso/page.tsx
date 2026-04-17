"use client";

import Link from "next/link";
import { useState } from "react";
import { Loader2, Plus, Trash2 } from "lucide-react";

import { PageHeader } from "@/components/data/page-header";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { useDeleteSSOProvider, useSSOProviders } from "@/features/sso/hooks";
import type { SSOProvider } from "@/features/sso/types";

export default function SSOSettingsPage() {
  const { data, isLoading, error } = useSSOProviders();
  const [pendingDelete, setPendingDelete] = useState<SSOProvider | null>(null);
  const deleter = useDeleteSSOProvider();

  return (
    <div>
      <PageHeader
        title="SSO Providers"
        description="Configure OpenID Connect providers so your team can sign in with Azure AD, Okta, Keycloak, or any OIDC-compliant IdP."
        actions={
          <Button asChild>
            <Link href="/settings/sso/new">
              <Plus className="mr-2 h-4 w-4" />
              Add provider
            </Link>
          </Button>
        }
      />

      {isLoading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading providers…
        </div>
      )}
      {error && (
        <div className="p-3 text-sm text-destructive bg-destructive/10 rounded-md">
          {(error as Error).message}
        </div>
      )}
      {!isLoading && data && data.length === 0 && (
        <div className="text-center py-16 border rounded-md">
          <p className="text-sm text-muted-foreground mb-4">
            No SSO providers configured.
          </p>
          <Button asChild>
            <Link href="/settings/sso/new">
              <Plus className="mr-2 h-4 w-4" />
              Add your first provider
            </Link>
          </Button>
        </div>
      )}
      {!isLoading && data && data.length > 0 && (
        <div className="border rounded-md">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Display name</TableHead>
                <TableHead>Slug</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Default role</TableHead>
                <TableHead className="w-36 text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.map((p) => (
                <TableRow key={p.id}>
                  <TableCell className="font-medium">{p.display_name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {p.provider_slug}
                  </TableCell>
                  <TableCell>
                    {p.enabled ? (
                      <Badge variant="default">enabled</Badge>
                    ) : (
                      <Badge variant="secondary">disabled</Badge>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {p.default_role_id}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button size="sm" variant="outline" asChild>
                      <Link href={`/settings/sso/${p.id}`}>Edit</Link>
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="ml-2 text-destructive"
                      onClick={() => setPendingDelete(p)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}

      <Dialog
        open={!!pendingDelete}
        onOpenChange={(open) => !open && setPendingDelete(null)}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete SSO provider</DialogTitle>
            <DialogDescription>
              Users who rely on <strong>{pendingDelete?.display_name}</strong>{" "}
              will no longer be able to sign in via SSO. Existing sessions stay
              valid until they expire. This cannot be undone.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setPendingDelete(null)}
              disabled={deleter.isPending}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={() => {
                if (!pendingDelete) return;
                deleter.mutate(pendingDelete.id, {
                  onSettled: () => setPendingDelete(null),
                });
              }}
              disabled={deleter.isPending}
            >
              {deleter.isPending && (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              )}
              Delete
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
