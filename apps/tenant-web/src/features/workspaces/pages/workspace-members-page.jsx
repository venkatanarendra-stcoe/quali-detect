import { Users } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { PageHeader } from "@/components/common/page-header.jsx";
import { Pager } from "@/components/common/pager.jsx";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useActiveWorkspace, useCan } from "@/features/authorization/hooks/use-permissions.js";
import { AddAccessDialog } from "../components/add-access-dialog.jsx";
import {
  useRemoveWorkspaceMember,
  useRevokeAssignment,
  useWorkspaceAssignments,
  useWorkspaceMembers,
} from "../hooks/use-workspaces.js";

const date = (value) =>
  new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
const when = (a) => (a.expiresAt ? ` · until ${date(a.expiresAt)}` : "");

function RoleBadges({ assignments }) {
  if (assignments.length === 0) return <span className="text-muted-foreground">No role</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {assignments.map((a) => (
        <Badge key={a.id} tone={a.status === "suspended" ? "danger" : "neutral"}>
          {a.role.name}
          {a.status === "suspended" ? " (suspended)" : ""}
          {when(a)}
        </Badge>
      ))}
    </span>
  );
}

/**
 * T-40 Members & Groups of a workspace. People: the roster with each person's workspace roles. Groups: groups holding a
 * workspace role. Managing needs `workspace.manage_members` in this workspace and, to pick people and roles, tenant-level
 * view permissions; every refusal is explained on the disabled control. The API enforces all of it.
 */
export function WorkspaceMembersPage() {
  const active = useActiveWorkspace();
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const page = Math.max(1, Number(params.get("page")) || 1);
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState(null);
  const [revoking, setRevoking] = useState(null);
  const canViewRoles = can("workspace.view_roles");
  const archived = active.status === "archived";

  const members = useWorkspaceMembers(active.id, { page, pageSize: 20, sort: "name:asc" });
  const assignments = useWorkspaceAssignments(
    active.id,
    { pageSize: 100, sort: "createdAt:desc" },
    { enabled: canViewRoles },
  );
  const removeMember = useRemoveWorkspaceMember(active.id);
  const revoke = useRevokeAssignment(active.id);

  let addReason = null;
  if (!can("workspace.manage_members"))
    addReason = "You need the workspace.manage_members permission to add access.";
  else if (archived) addReason = "This workspace is archived and read-only.";
  else if (!can("user.view") || !can("role.view"))
    addReason =
      "Choosing people and roles needs permission to view organization members and roles.";
  const manageReason = !can("workspace.manage_members")
    ? "You need the workspace.manage_members permission."
    : archived
      ? "This workspace is archived and read-only."
      : null;

  const all = assignments.data?.items ?? [];
  const userAssignments = (userId) =>
    all.filter((a) => a.subjectType === "user" && a.subject.id === userId);
  const groupAssignments = all.filter((a) => a.subjectType === "group");

  return (
    <>
      <PageHeader
        title="Members & groups"
        description="People and groups in this workspace. Access comes from role assignments, not from being listed."
        actions={
          <DisabledWithReason reason={addReason}>
            <Button onClick={() => setAdding(true)}>Add access</Button>
          </DisabledWithReason>
        }
      />
      {archived ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          This workspace is archived: membership is read-only until it is restored.
        </p>
      ) : null}

      <Tabs defaultValue="people">
        <TabsList aria-label="Members and groups">
          <TabsTrigger value="people">
            People{members.data?.pagination ? ` (${members.data.pagination.totalItems})` : ""}
          </TabsTrigger>
          <TabsTrigger value="groups">
            Groups{canViewRoles && assignments.data ? ` (${groupAssignments.length})` : ""}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="people">
          {members.isPending ? <LoadingState label="Loading members" /> : null}
          {members.isError ? (
            <QueryErrorState error={members.error} onRetry={members.refetch} />
          ) : null}
          {members.data && members.data.items.length === 0 ? (
            <EmptyState
              icon={Users}
              title="No members yet"
              description="People added to this workspace appear here."
            />
          ) : null}
          {members.data && members.data.items.length > 0 ? (
            <>
              <div className="relative overflow-x-auto rounded-md border border-border bg-card">
                <table className="w-full text-left text-[13px] leading-5">
                  <caption className="sr-only">Workspace members</caption>
                  <thead className="border-b border-border text-muted-foreground">
                    <tr>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Member
                      </th>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Email
                      </th>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Workspace role
                      </th>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Status
                      </th>
                      <th scope="col" className="px-3 py-2 font-medium">
                        Added
                      </th>
                      <th scope="col" className="px-3 py-2">
                        <span className="sr-only">Actions</span>
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {members.data.items.map((m) => (
                      <tr
                        key={m.userId}
                        className="min-h-9 border-b border-border align-top last:border-0 hover:bg-secondary"
                      >
                        <td className="px-3 py-2 font-medium">{m.name}</td>
                        <td className="px-3 py-2 text-muted-foreground">{m.email}</td>
                        <td className="px-3 py-2">
                          {canViewRoles ? (
                            assignments.isPending ? (
                              <span className="text-muted-foreground">Loading…</span>
                            ) : (
                              <RoleBadges assignments={userAssignments(m.userId)} />
                            )
                          ) : (
                            <span className="text-muted-foreground">
                              Hidden (needs workspace.view_roles)
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2">
                          <StatusChip status={m.status} />
                        </td>
                        <td className="px-3 py-2 text-muted-foreground">{date(m.addedAt)}</td>
                        <td className="px-3 py-1.5 text-right">
                          <DisabledWithReason reason={manageReason}>
                            <Button size="sm" variant="ghost" onClick={() => setRemoving(m)}>
                              Remove
                            </Button>
                          </DisabledWithReason>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager
                pagination={members.data.pagination}
                onPage={(p) => setParams(p > 1 ? { page: String(p) } : {}, { replace: true })}
              />
            </>
          ) : null}
        </TabsContent>

        <TabsContent value="groups">
          {!canViewRoles ? (
            <EmptyState
              title="Roles are hidden"
              description="Seeing which groups hold roles needs the workspace.view_roles permission."
            />
          ) : null}
          {canViewRoles && assignments.isPending ? <LoadingState label="Loading groups" /> : null}
          {canViewRoles && assignments.isError ? (
            <QueryErrorState error={assignments.error} onRetry={assignments.refetch} />
          ) : null}
          {canViewRoles && assignments.data && groupAssignments.length === 0 ? (
            <EmptyState
              icon={Users}
              title="No groups yet"
              description="Groups given a role in this workspace appear here."
            />
          ) : null}
          {canViewRoles && groupAssignments.length > 0 ? (
            <div className="relative overflow-x-auto rounded-md border border-border bg-card">
              <table className="w-full text-left text-[13px] leading-5">
                <caption className="sr-only">Groups with a workspace role</caption>
                <thead className="border-b border-border text-muted-foreground">
                  <tr>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Group
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Workspace role
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Expires
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">
                      Added
                    </th>
                    <th scope="col" className="px-3 py-2">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {groupAssignments.map((a) => (
                    <tr
                      key={a.id}
                      className="h-9 border-b border-border last:border-0 hover:bg-secondary"
                    >
                      <td className="px-3 font-medium">{a.subject.name}</td>
                      <td className="px-3">
                        <RoleBadges assignments={[a]} />
                      </td>
                      <td className="px-3 text-muted-foreground">
                        {a.expiresAt ? date(a.expiresAt) : "Never"}
                      </td>
                      <td className="px-3 text-muted-foreground">{date(a.createdAt)}</td>
                      <td className="px-3 text-right">
                        <DisabledWithReason reason={manageReason}>
                          <Button size="sm" variant="ghost" onClick={() => setRevoking(a)}>
                            Revoke
                          </Button>
                        </DisabledWithReason>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </TabsContent>
      </Tabs>

      <AddAccessDialog workspace={active} open={adding} onOpenChange={setAdding} />
      <ConfirmDialog
        open={Boolean(removing)}
        onOpenChange={(o) => !o && (setRemoving(null), removeMember.reset())}
        title={`Remove ${removing?.name ?? "member"}?`}
        description="They are removed from this workspace and lose their workspace roles here. Their access in other workspaces is not affected."
        confirmLabel="Remove member"
        destructive
        pending={removeMember.isPending}
        error={removeMember.error}
        onConfirm={() =>
          removeMember.mutate(removing.userId, {
            onSuccess: () => {
              toast.success(`${removing.name} removed`);
              setRemoving(null);
            },
          })
        }
      />
      <ConfirmDialog
        open={Boolean(revoking)}
        onOpenChange={(o) => !o && (setRevoking(null), revoke.reset())}
        title={`Revoke ${revoking?.role.name ?? "role"} from ${revoking?.subject.name ?? "group"}?`}
        description="Members of the group lose the access this role gave them in this workspace."
        confirmLabel="Revoke access"
        destructive
        pending={revoke.isPending}
        error={revoke.error}
        onConfirm={() =>
          revoke.mutate(revoking.id, {
            onSuccess: () => {
              toast.success("Access revoked");
              setRevoking(null);
            },
          })
        }
      />
    </>
  );
}
