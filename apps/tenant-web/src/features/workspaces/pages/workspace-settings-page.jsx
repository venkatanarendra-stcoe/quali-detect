import { zodResolver } from "@hookform/resolvers/zod";
import { Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { AppPageLayout } from "@qmentisai/ui";
import { SearchPicker } from "@/components/common/search-picker.jsx";
import { StatusChip } from "@/components/common/status-chip.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useActiveWorkspace, useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useUserSearch } from "@/features/directory/hooks/use-directory.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import {
  useArchiveWorkspace,
  useRestoreWorkspace,
  useUpdateWorkspace,
  useWorkspaceDetail,
} from "../hooks/use-workspaces.js";

const schema = z.object({
  name: z.string().trim().min(1, "Enter a workspace name.").max(120, "Use at most 120 characters."),
  description: z.string().trim().max(1000, "Use at most 1000 characters."),
  businessUnit: z.string().trim().max(120, "Use at most 120 characters."),
});
const dateTime = (value) =>
  new Date(value).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

function SettingsForm({ workspace }) {
  const can = useCan();
  const update = useUpdateWorkspace(workspace.id);
  const [owner, setOwner] = useState(null); // null = unchanged
  const [ownerQuery, setOwnerQuery] = useState("");
  const [formError, setFormError] = useState(null);
  const archived = workspace.status === "archived";
  const canEdit = can("workspace.update") && !archived;
  const canPickOwner = can("user.view");
  const debounced = useDebouncedValue(ownerQuery);
  const ownerSearch = useUserSearch(debounced, { enabled: canPickOwner && canEdit });
  const defaults = {
    name: workspace.name,
    description: workspace.description ?? "",
    businessUnit: workspace.businessUnit ?? "",
  };
  const {
    register,
    handleSubmit,
    reset,
    setError,
    formState: { errors, isDirty },
  } = useForm({ resolver: zodResolver(schema), defaultValues: defaults });
  const dirty = isDirty || owner !== null;

  useEffect(() => {
    if (!dirty) return undefined;
    const warn = (event) => event.preventDefault();
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [dirty]);

  const onSubmit = handleSubmit(async (values) => {
    setFormError(null);
    const body = {};
    if (values.name !== workspace.name) body.name = values.name;
    if (values.description !== (workspace.description ?? ""))
      body.description = values.description === "" ? null : values.description;
    if (values.businessUnit !== (workspace.businessUnit ?? ""))
      body.businessUnit = values.businessUnit === "" ? null : values.businessUnit;
    if (owner) body.ownerUserId = owner.id;
    if (Object.keys(body).length === 0) return;
    try {
      const saved = await update.mutateAsync(body);
      reset({
        name: saved.name,
        description: saved.description ?? "",
        businessUnit: saved.businessUnit ?? "",
      });
      setOwner(null);
      toast.success("Workspace updated");
    } catch (error) {
      if (isApiError(error) && error.status === 409 && error.details?.field === "name")
        setError("name", { message: "A workspace with this name already exists." });
      else setFormError(error);
    }
  });

  return (
    <form onSubmit={onSubmit} noValidate>
      <fieldset disabled={!canEdit} className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="s-name">Name</Label>
          <Input
            id="s-name"
            aria-invalid={Boolean(errors.name)}
            aria-describedby={errors.name ? "s-name-error" : undefined}
            {...register("name")}
          />
          {errors.name ? (
            <p id="s-name-error" role="alert" className="text-xs text-status-danger">
              {errors.name.message}
            </p>
          ) : null}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="s-description">Description</Label>
          <Textarea
            id="s-description"
            aria-invalid={Boolean(errors.description)}
            {...register("description")}
          />
          {errors.description ? (
            <p role="alert" className="text-xs text-status-danger">
              {errors.description.message}
            </p>
          ) : null}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="s-bu">Business unit</Label>
          <Input
            id="s-bu"
            aria-invalid={Boolean(errors.businessUnit)}
            {...register("businessUnit")}
          />
          {errors.businessUnit ? (
            <p role="alert" className="text-xs text-status-danger">
              {errors.businessUnit.message}
            </p>
          ) : null}
        </div>
        {canPickOwner && canEdit ? (
          <SearchPicker
            id="s-owner"
            label="Owner"
            placeholder="Search by name or email"
            query={ownerQuery}
            onQueryChange={setOwnerQuery}
            options={(ownerSearch.data ?? []).map((u) => ({
              id: u.userId,
              label: u.name ?? u.email,
              hint: u.email,
            }))}
            isLoading={ownerSearch.isFetching}
            error={ownerSearch.error}
            selected={
              owner ??
              (workspace.ownerUserId
                ? { id: workspace.ownerUserId, label: workspace.ownerName ?? "Owner" }
                : null)
            }
            onSelect={setOwner}
            onClear={() => setOwner({ id: null, label: "" })}
          />
        ) : (
          <div className="space-y-1.5">
            <Label>Owner</Label>
            <p className="text-sm">{workspace.ownerName ?? "—"}</p>
            {canEdit ? (
              <p className="text-xs text-subtle-foreground">
                Changing the owner needs permission to view organization members.
              </p>
            ) : null}
          </div>
        )}
      </fieldset>
      {formError ? (
        <p role="alert" className="mt-4 text-sm text-status-danger">
          {describeError(formError)}
        </p>
      ) : null}
      <div className="mt-6 flex items-center gap-3">
        <DisabledWithReason
          reason={
            !can("workspace.update")
              ? "You need the workspace.update permission to edit settings."
              : archived
                ? "This workspace is archived and read-only."
                : null
          }
        >
          <Button type="submit" disabled={!dirty || update.isPending}>
            {update.isPending ? "Saving…" : "Save changes"}
          </Button>
        </DisabledWithReason>
        {dirty && canEdit ? (
          <span className="text-xs text-muted-foreground" role="status">
            You have unsaved changes.
          </span>
        ) : null}
      </div>
    </form>
  );
}

/**
 * T-44 Workspace settings: edit details, change the owner, archive or restore. Read-only while archived or without
 * `workspace.update`; archive and restore need `workspace.archive`. Archiving requires typing the workspace name.
 */
export function WorkspaceSettingsPage() {
  const active = useActiveWorkspace();
  const can = useCan();
  const detail = useWorkspaceDetail(active.id);
  const archive = useArchiveWorkspace(active.id);
  const restore = useRestoreWorkspace(active.id);
  const [archiving, setArchiving] = useState(false);
  const [restoring, setRestoring] = useState(false);

  if (detail.isPending) return <LoadingState rows={4} label="Loading settings" />;
  if (detail.isError) return <QueryErrorState error={detail.error} onRetry={detail.refetch} />;
  const ws = detail.data;
  const archived = ws.status === "archived";
  const copyId = async () => {
    try {
      await navigator.clipboard.writeText(ws.id);
      toast.success("Workspace ID copied");
    } catch {
      toast.error("Could not copy. Select the ID and copy it manually.");
    }
  };
  const archiveReason = !can("workspace.archive")
    ? "You need the workspace.archive permission."
    : null;

  return (
    <AppPageLayout
      title="Workspace settings"
      description={ws.name}
      actions={<StatusChip status={ws.status} />}
    >
      {archived ? (
        <p
          role="status"
          className="mb-4 rounded-md border border-border-strong bg-secondary p-3 text-sm"
        >
          This workspace is archived and read-only. Restore it to make changes.
        </p>
      ) : null}
      <div className="grid max-w-3xl gap-6">
        <Card>
          <CardHeader>
            <CardTitle>General</CardTitle>
            <CardDescription>Name, description, business unit and owner.</CardDescription>
          </CardHeader>
          <CardContent>
            <SettingsForm key={`${ws.id}-${ws.updatedAt}`} workspace={ws} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Information</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="space-y-2 text-sm">
              <div className="flex flex-wrap items-center gap-2">
                <dt className="w-24 text-muted-foreground">ID</dt>
                <dd className="flex items-center gap-1">
                  <span className="font-mono text-xs">{ws.id}</span>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="size-6"
                    aria-label="Copy workspace ID"
                    onClick={copyId}
                  >
                    <Copy aria-hidden="true" className="size-3.5" />
                  </Button>
                </dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-24 text-muted-foreground">Members</dt>
                <dd>{ws.memberCount}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-24 text-muted-foreground">Created</dt>
                <dd>{dateTime(ws.createdAt)}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="w-24 text-muted-foreground">Updated</dt>
                <dd>{dateTime(ws.updatedAt)}</dd>
              </div>
              {archived && ws.archivedAt ? (
                <div className="flex gap-2">
                  <dt className="w-24 text-muted-foreground">Archived</dt>
                  <dd>{dateTime(ws.archivedAt)}</dd>
                </div>
              ) : null}
            </dl>
          </CardContent>
        </Card>
        <Card className="border-border-strong">
          <CardHeader>
            <CardTitle>{archived ? "Restore workspace" : "Archive workspace"}</CardTitle>
            <CardDescription>
              {archived
                ? "Make the workspace active again. Restoring counts against your plan's workspace limit."
                : "An archived workspace becomes read-only. Nothing is deleted and it can be restored."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <DisabledWithReason reason={archiveReason}>
              {archived ? (
                <Button variant="secondary" onClick={() => setRestoring(true)}>
                  Restore workspace
                </Button>
              ) : (
                <Button variant="destructive" onClick={() => setArchiving(true)}>
                  Archive workspace
                </Button>
              )}
            </DisabledWithReason>
          </CardContent>
        </Card>
      </div>
      <ConfirmDialog
        open={archiving}
        onOpenChange={(o) => {
          setArchiving(o);
          if (!o) archive.reset();
        }}
        title="Archive this workspace?"
        description="It becomes read-only for everyone. Members keep their roles, and you can restore it later."
        confirmLabel="Archive workspace"
        destructive
        confirmText={ws.name}
        pending={archive.isPending}
        error={archive.error}
        onConfirm={() =>
          archive.mutate(undefined, {
            onSuccess: () => {
              toast.success("Workspace archived");
              setArchiving(false);
            },
          })
        }
      />
      <ConfirmDialog
        open={restoring}
        onOpenChange={(o) => {
          setRestoring(o);
          if (!o) restore.reset();
        }}
        title="Restore this workspace?"
        description="It becomes active and editable again."
        confirmLabel="Restore workspace"
        pending={restore.isPending}
        error={restore.error}
        onConfirm={() =>
          restore.mutate(undefined, {
            onSuccess: () => {
              toast.success("Workspace restored");
              setRestoring(false);
            },
          })
        }
      />
    </AppPageLayout>
  );
}
