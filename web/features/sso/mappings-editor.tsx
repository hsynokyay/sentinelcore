"use client";

import { useState } from "react";
import { Loader2, Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  useCreateSSOMapping,
  useDeleteSSOMapping,
  useSSOMappings,
} from "./hooks";

const ROLE_IDS = [
  { id: "owner", label: "Owner" },
  { id: "admin", label: "Admin" },
  { id: "security_engineer", label: "Security Engineer" },
  { id: "auditor", label: "Auditor" },
  { id: "developer", label: "Developer" },
];

interface MappingsEditorProps {
  providerId: string;
}

/**
 * Inline editor for the provider's IdP group → SentinelCore role
 * mappings. Lower priority wins; ties broken by role ID ASC.
 *
 * Creating a row for an existing group_claim UPDATES the row (upsert
 * semantics at the backend). Deleting is idempotent.
 */
export function MappingsEditor({ providerId }: MappingsEditorProps) {
  const { data: mappings, isLoading } = useSSOMappings(providerId);
  const createMutation = useCreateSSOMapping(providerId);
  const deleteMutation = useDeleteSSOMapping(providerId);

  const [group, setGroup] = useState("");
  const [role, setRole] = useState("developer");
  const [priority, setPriority] = useState(100);
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="border rounded-md p-4 space-y-4">
      <div>
        <h3 className="text-base font-semibold">Group → Role mappings</h3>
        <p className="text-xs text-muted-foreground">
          When a user's IdP groups match a mapping, they're assigned that
          role. The mapping with the lowest priority number wins.
        </p>
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          setError(null);
          if (!group.trim()) {
            setError("Group claim is required");
            return;
          }
          if (priority < 1 || priority > 10000) {
            setError("Priority must be 1–10000");
            return;
          }
          createMutation.mutate(
            { group_claim: group.trim(), role_id: role, priority },
            {
              onSuccess: () => {
                setGroup("");
                setPriority(100);
              },
              onError: (e) => setError((e as Error).message),
            },
          );
        }}
        className="grid grid-cols-[1fr,180px,100px,auto] gap-2 items-end"
      >
        <div className="space-y-1">
          <Label htmlFor="group_claim">Group claim</Label>
          <Input
            id="group_claim"
            value={group}
            onChange={(e) => setGroup(e.target.value)}
            placeholder="security-engineers"
          />
        </div>
        <div className="space-y-1">
          <Label htmlFor="role_id">Role</Label>
          <Select value={role} onValueChange={setRole}>
            <SelectTrigger id="role_id">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ROLE_IDS.map((r) => (
                <SelectItem key={r.id} value={r.id}>
                  {r.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1">
          <Label htmlFor="priority">Priority</Label>
          <Input
            id="priority"
            type="number"
            min={1}
            max={10000}
            value={priority}
            onChange={(e) => setPriority(Number(e.target.value))}
          />
        </div>
        <Button type="submit" disabled={createMutation.isPending}>
          {createMutation.isPending ? (
            <Loader2 className="h-4 w-4 animate-spin" />
          ) : (
            <Plus className="h-4 w-4" />
          )}
        </Button>
      </form>

      {error && (
        <div className="p-2 text-xs text-destructive bg-destructive/10 rounded">
          {error}
        </div>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : mappings && mappings.length > 0 ? (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Group claim</TableHead>
              <TableHead>Role</TableHead>
              <TableHead className="w-24">Priority</TableHead>
              <TableHead className="w-16" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {mappings.map((m) => (
              <TableRow key={m.id}>
                <TableCell className="font-mono text-xs">{m.group_claim}</TableCell>
                <TableCell className="font-mono text-xs">{m.role_id}</TableCell>
                <TableCell>{m.priority}</TableCell>
                <TableCell>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-destructive"
                    onClick={() => deleteMutation.mutate(m.id)}
                    disabled={deleteMutation.isPending}
                  >
                    <Trash2 className="h-4 w-4" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : (
        <p className="text-xs text-muted-foreground">
          No group mappings yet. Without mappings every SSO user gets the
          provider's default role.
        </p>
      )}
    </div>
  );
}
