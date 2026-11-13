import { AppPageLayout } from "@qmentisai/ui";
import { Users } from "lucide-react";
import { useState } from "react";
import { useSearchParams } from "react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { QueryTable } from "@/components/common/query-table.jsx";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { ScrollTabs, ScrollTabsContent } from "@/components/ui/scroll-tabs.jsx";
import { TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
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

  const peopleColumns = [
    {
      id: "name",
      header: "Member",
      enableSorting: false,
      meta: { className: "font-medium" },
      cell: ({ row: { original: m } }) => m.name,
    },
    {
      id: "email",
      header: "Email",
      enableSorting: false,
      meta: { className: "text-muted-foreground" },
      cell: ({ row: { original: m } }) => m.email,
    },
    {
      id: "role",
      header: "Workspace role",
      enableSorting: false,
      cell: ({ row: { original: m } }) =>
        canViewRoles ? (
          assignments.isPending ? (
            <span className="text-muted-foreground">Loading…</span>
          ) : (
            <RoleBadges assignments={userAssignments(m.userId)} />
          )
        ) : (
          <span className="text-muted-foreground">Hidden (needs workspace.view_roles)</span>
        ),
    },
    {
      id: "status",
      header: "Status",
      enableSorting: false,
      cell: ({ row: { original: m } }) => <StatusChip status={m.status} />,
    },
    {
      id: "added",
      header: "Added",
      enableSorting: false,
      meta: { className: "text-muted-foreground" },
      cell: ({ row: { original: m } }) => date(m.addedAt),
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      meta: { className: "text-right" },
      cell: ({ row: { original: m } }) => (
        <DisabledWithReason reason={manageReason}>
          <Button size="sm" variant="ghost" onClick={() => setRemoving(m)}>
            Remove
          </Button>
        </DisabledWithReason>
      ),
    },
  ];
  const groupColumns = [
    {
      id: "group",
      header: "Group",
      enableSorting: false,
      meta: { className: "font-medium" },
      cell: ({ row: { original: a } }) => a.subject.name,
    },
    {
      id: "role",
      header: "Workspace role",
      enableSorting: false,
      cell: ({ row: { original: a } }) => <RoleBadges assignments={[a]} />,
    },
    {
      id: "expires",
      header: "Expires",
      enableSorting: false,
      meta: { className: "text-muted-foreground" },
      cell: ({ row: { original: a } }) => (a.expiresAt ? date(a.expiresAt) : "Never"),
    },
    {
      id: "added",
      header: "Added",
      enableSorting: false,
      meta: { className: "text-muted-foreground" },
      cell: ({ row: { original: a } }) => date(a.createdAt),
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      enableSorting: false,
      meta: { className: "text-right" },
      cell: ({ row: { original: a } }) => (
        <DisabledWithReason reason={manageReason}>
          <Button size="sm" variant="ghost" onClick={() => setRevoking(a)}>
            Revoke
          </Button>
        </DisabledWithReason>
      ),
    },
  ];

  // The Groups table reads the assignments query; without workspace.view_roles it shows the "Roles are hidden" state.
  const groupsQuery = canViewRoles
    ? assignments
    : { isPending: false, isError: false, error: null, refetch: () => {} };
  return (
    <AppPageLayout
      title="Members & groups"
      description="People and groups in this workspace. Access comes from role assignments, not from being listed."
      actions={
        <DisabledWithReason reason={addReason}>
          <Button onClick={() => setAdding(true)}>Add access</Button>
        </DisabledWithReason>
      }
      scroll={false}
    >
      {archived ? (
        <p
          role="status"
          className="mb-4 shrink-0 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          This workspace is archived: membership is read-only until it is restored.
        </p>
      ) : null}

      <ScrollTabs defaultValue="people">
        <TabsList aria-label="Members and groups" className="shrink-0">
          <TabsTrigger value="people">
            People{members.data?.pagination ? ` (${members.data.pagination.totalItems})` : ""}
          </TabsTrigger>
          <TabsTrigger value="groups">
            Groups{canViewRoles && assignments.data ? ` (${groupAssignments.length})` : ""}
          </TabsTrigger>
        </TabsList>

        <ScrollTabsContent value="people" className="flex flex-col overflow-hidden pb-0">
          <QueryTable
            caption="Workspace members"
            query={members}
            columns={peopleColumns}
            getRowId={(m) => m.userId}
            pagination={members.data?.pagination}
            onPage={(p) => setParams(p > 1 ? { page: String(p) } : {}, { replace: true })}
            emptyState={
              <EmptyState
                icon={Users}
                title="No members yet"
                description="People added to this workspace appear here."
              />
            }
          />
        </ScrollTabsContent>

        <ScrollTabsContent value="groups" className="flex flex-col overflow-hidden pb-0">
          <QueryTable
            caption="Groups with a workspace role"
            query={groupsQuery}
            items={groupAssignments}
            columns={groupColumns}
            getRowId={(a) => a.id}
            emptyState={
              canViewRoles ? (
                <EmptyState
                  icon={Users}
                  title="No groups yet"
                  description="Groups given a role in this workspace appear here."
                />
              ) : (
                <EmptyState
                  title="Roles are hidden"
                  description="Seeing which groups hold roles needs the workspace.view_roles permission."
                />
              )
            }
          />
        </ScrollTabsContent>
      </ScrollTabs>

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
    </AppPageLayout>
  );
}
