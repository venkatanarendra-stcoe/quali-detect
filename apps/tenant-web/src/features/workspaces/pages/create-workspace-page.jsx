import { AppPageLayout, ComboboxAddRow, Stepper } from "@qmentisai/ui";
import { zodResolver } from "@hookform/resolvers/zod";
import { CircleAlert, CircleCheck } from "lucide-react";
import { useCallback, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { Link, useNavigate } from "react-router";
import { toast } from "sonner";
import { z } from "zod";
import { SearchPicker } from "@/components/common/search-picker.jsx";
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
import { useSession } from "@/features/auth/hooks/use-session.js";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { useAssignableRoles, useUserSearch } from "@/features/directory/hooks/use-directory.js";
import { directoryService } from "@/features/directory/services/directory-service.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import { useCreateWorkspace, useRefreshWorkspaces } from "../hooks/use-workspaces.js";
import { workspacesService } from "../services/workspaces-service.js";

const STEPS = ["Details", "Members & access", "Review"];
const detailsSchema = z.object({
  name: z.string().trim().min(1, "Enter a workspace name.").max(120, "Use at most 120 characters."),
  description: z.string().trim().max(1000, "Use at most 1000 characters."),
  businessUnit: z.string().trim().max(120, "Use at most 120 characters."),
});
const blankToUndefined = (value) => (value === "" ? undefined : value);

const TO_ITEM = (r) => ({
  key: r.key,
  type: r.kind,
  value: r.id,
  label: r.label,
  role: r.roleId,
  roleLabel: r.roleName,
});
const TO_ROW = (i) => ({
  key: i.key,
  kind: i.type,
  id: i.value,
  label: i.label,
  roleId: i.role,
  roleName: i.roleLabel,
});

/** People/group + role rows the creator wants to grant right after the workspace exists. */
function AccessStep({ rows, setRows, ownerId, canPeople, canGroups }) {
  const roles = useAssignableRoles();
  const typeOptions = [
    { value: "person", label: "Person", disabled: !canPeople },
    { value: "group", label: "Group", disabled: !canGroups },
  ];
  const roleOptions = (roles.data ?? []).map((r) => ({ value: r.id, label: r.name }));
  const loadOptions = useCallback(async (query, { type, signal }) => {
    if (type === "person") {
      const page = await directoryService.users(
        { q: query || undefined, status: "active", pageSize: 20, sort: "name:asc" },
        { signal },
      );
      return page.items.map((u) => ({
        value: u.userId,
        label: u.name ?? u.email,
        description: u.email,
      }));
    }
    const page = await directoryService.groups(
      { q: query || undefined, pageSize: 20, sort: "name:asc" },
      { signal },
    );
    return page.items.map((g) => ({
      value: g.id,
      label: g.name,
      description: `${g.memberCount} ${g.memberCount === 1 ? "member" : "members"}`,
    }));
  }, []);

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        The owner is added as Admin automatically. Group membership alone grants no access; the role
        assigned to the group does. You can also do this later from Members &amp; groups.
      </p>
      <ComboboxAddRow
        typeOptions={typeOptions}
        defaultType={canPeople ? "person" : "group"}
        loadOptions={loadOptions}
        roleOptions={roleOptions}
        roleLoading={roles.isPending}
        subjectLabel="Person or group"
        subjectPlaceholder="Search people or groups"
        listLabel="Access to grant"
        emptyListText="No one added yet."
        items={rows.map(TO_ITEM)}
        onItemsChange={(items) => setRows(items.map(TO_ROW))}
        validateAdd={(item) =>
          item.type === "person" && item.value === ownerId
            ? "The owner already has Admin access to the new workspace."
            : null
        }
      />
      {roles.isError ? (
        <p role="alert" className="text-sm text-status-danger">
          {describeError(roles.error)}
        </p>
      ) : null}
    </div>
  );
}

function ReviewRow({ label, children }) {
  return (
    <div className="grid grid-cols-[10rem_1fr] gap-2 py-1.5 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

/**
 * T-08 Create workspace (wizard): Details, Members & access, Review. The policies step of the design arrives with the
 * policy module. Creating happens first; access grants follow one by one, and a partial failure leaves the workspace in
 * place with a retry list (nothing is created twice).
 */
export function CreateWorkspacePage() {
  const navigate = useNavigate();
  const can = useCan();
  const { me } = useSession();
  const createWorkspace = useCreateWorkspace();
  const refresh = useRefreshWorkspaces();
  const [step, setStep] = useState(0);
  const [rows, setRows] = useState([]);
  const [owner, setOwner] = useState(null);
  const [ownerQuery, setOwnerQuery] = useState("");
  const [submitError, setSubmitError] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [created, setCreated] = useState(null); // { workspace, results: [{ row, state, error? }] }

  const canOwner = can("user.view");
  const canPeople = can("user.view") && can("role.view");
  const canGroups = can("group.view") && can("role.view");
  const canAccess = canPeople || canGroups;
  const debouncedOwner = useDebouncedValue(ownerQuery);
  const ownerSearch = useUserSearch(debouncedOwner, { enabled: canOwner && step === 0 });
  const form = useForm({
    resolver: zodResolver(detailsSchema),
    defaultValues: { name: "", description: "", businessUnit: "" },
  });
  const {
    register,
    trigger,
    setError,
    control,
    formState: { errors },
  } = form;
  const details = useWatch({ control });

  const next = async () => {
    if (step === 0 && !(await trigger())) return;
    setStep(step + 1);
  };

  async function grantAll(workspace, pending) {
    const results = [];
    for (const row of pending) {
      try {
        await workspacesService.createAssignment(workspace.id, {
          subjectType: row.kind === "person" ? "user" : "group",
          subjectId: row.id,
          roleId: row.roleId,
        });
        results.push({ row, state: "ok" });
      } catch (error) {
        results.push({ row, state: "failed", error });
      }
    }
    return results;
  }

  async function submit() {
    setSubmitError(null);
    setSubmitting(true);
    try {
      let workspace = created?.workspace;
      if (!workspace) {
        const values = form.getValues();
        try {
          workspace = await createWorkspace.mutateAsync({
            name: values.name,
            description: blankToUndefined(values.description),
            businessUnit: blankToUndefined(values.businessUnit),
            ownerUserId: owner?.id,
          });
        } catch (error) {
          if (isApiError(error) && error.status === 409 && error.details?.field === "name") {
            setError("name", { message: "A workspace with this name already exists." });
            setStep(0);
          } else {
            setSubmitError(error);
          }
          return;
        }
      }
      const pending = created
        ? created.results.filter((r) => r.state === "failed").map((r) => r.row)
        : rows;
      const fresh = await grantAll(workspace, pending);
      const results = [...(created?.results.filter((r) => r.state === "ok") ?? []), ...fresh];
      await refresh(); // the new workspace must be in the session before its pages open
      if (results.every((r) => r.state === "ok")) {
        toast.success(`Workspace "${workspace.name}" created`);
        navigate(`/workspaces/${workspace.id}/members`, { replace: true });
      } else {
        setCreated({ workspace, results });
      }
    } finally {
      setSubmitting(false);
    }
  }

  if (created) {
    const failed = created.results.filter((r) => r.state === "failed");
    return (
      <AppPageLayout
        title="Workspace created"
        description={`"${created.workspace.name}" exists. ${failed.length} of ${created.results.length} access grants did not apply.`}
      >
        <Card className="max-w-2xl">
          <CardContent className="space-y-3 pt-4">
            <ul className="divide-y divide-border">
              {created.results.map(({ row, state, error }) => (
                <li key={row.key} className="flex items-start gap-2 py-2 text-sm">
                  {state === "ok" ? (
                    <CircleCheck aria-hidden="true" className="mt-0.5 size-4 text-status-success" />
                  ) : (
                    <CircleAlert aria-hidden="true" className="mt-0.5 size-4 text-status-danger" />
                  )}
                  <div>
                    <p>
                      {row.label} · {row.roleName}
                    </p>
                    {state === "failed" ? (
                      <p className="text-xs text-status-danger">{describeError(error)}</p>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
            {submitError ? (
              <p role="alert" className="text-sm text-status-danger">
                {describeError(submitError)}
              </p>
            ) : null}
            <div className="flex gap-2">
              <Button onClick={submit} disabled={submitting}>
                {submitting ? "Retrying…" : "Retry failed"}
              </Button>
              <Button
                variant="secondary"
                onClick={() => navigate(`/workspaces/${created.workspace.id}/members`)}
              >
                Open workspace
              </Button>
            </div>
          </CardContent>
        </Card>
      </AppPageLayout>
    );
  }

  return (
    <AppPageLayout title="Create workspace" description="Set up a workspace for a team or product.">
      <div className="sticky top-0 z-10 -mt-1 mb-6 bg-background pt-1">
        <Stepper steps={STEPS} current={step} orientation="horizontal" />
      </div>
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <Card>
          <CardContent className="pt-4">
            {step === 0 ? (
              <form
                className="space-y-4"
                noValidate
                onSubmit={(e) => {
                  e.preventDefault();
                  next();
                }}
              >
                <div className="space-y-1.5">
                  <Label htmlFor="ws-name">Name</Label>
                  <Input
                    id="ws-name"
                    aria-invalid={Boolean(errors.name)}
                    aria-describedby={errors.name ? "ws-name-error" : undefined}
                    {...register("name")}
                  />
                  {errors.name ? (
                    <p id="ws-name-error" role="alert" className="text-xs text-status-danger">
                      {errors.name.message}
                    </p>
                  ) : null}
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="ws-description">
                    Description{" "}
                    <span className="font-normal text-muted-foreground">(optional)</span>
                  </Label>
                  <Textarea
                    id="ws-description"
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
                  <Label htmlFor="ws-bu">
                    Business unit{" "}
                    <span className="font-normal text-muted-foreground">(optional)</span>
                  </Label>
                  <Input
                    id="ws-bu"
                    aria-invalid={Boolean(errors.businessUnit)}
                    {...register("businessUnit")}
                  />
                  {errors.businessUnit ? (
                    <p role="alert" className="text-xs text-status-danger">
                      {errors.businessUnit.message}
                    </p>
                  ) : null}
                </div>
                {canOwner ? (
                  <SearchPicker
                    id="ws-owner"
                    label="Owner (defaults to you)"
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
                    selected={owner}
                    onSelect={setOwner}
                    onClear={() => setOwner(null)}
                  />
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Owner: you ({me.user.name}). Choosing someone else needs permission to view
                    organization members.
                  </p>
                )}
                <div className="flex justify-between pt-2">
                  <Button type="button" variant="ghost" asChild>
                    <Link to="/workspaces">Cancel</Link>
                  </Button>
                  <Button type="submit">Continue</Button>
                </div>
              </form>
            ) : null}
            {step === 1 ? (
              <div className="space-y-4">
                {canAccess ? (
                  <AccessStep
                    rows={rows}
                    setRows={setRows}
                    ownerId={owner?.id ?? me.user.id}
                    canPeople={canPeople}
                    canGroups={canGroups}
                  />
                ) : (
                  <p className="rounded-md border border-border bg-secondary p-3 text-sm">
                    Adding people or groups here needs permission to view members, groups and roles.
                    You can add access after creation from Members &amp; groups.
                  </p>
                )}
                <div className="flex justify-between pt-2">
                  <Button type="button" variant="ghost" onClick={() => setStep(0)}>
                    Back
                  </Button>
                  <Button type="button" onClick={next}>
                    Continue
                  </Button>
                </div>
              </div>
            ) : null}
            {step === 2 ? (
              <div className="space-y-4">
                <dl className="divide-y divide-border">
                  <ReviewRow label="Name">{details.name}</ReviewRow>
                  <ReviewRow label="Description">{details.description || "—"}</ReviewRow>
                  <ReviewRow label="Business unit">{details.businessUnit || "—"}</ReviewRow>
                  <ReviewRow label="Owner">{owner?.label ?? `${me.user.name} (you)`}</ReviewRow>
                  <ReviewRow label="Access to grant">
                    {rows.length === 0 ? (
                      "None (the owner is Admin)"
                    ) : (
                      <ul className="list-disc pl-4">
                        {rows.map((r) => (
                          <li key={r.key}>
                            {r.label} · {r.roleName}
                          </li>
                        ))}
                      </ul>
                    )}
                  </ReviewRow>
                </dl>
                <p className="rounded-md border border-border bg-secondary p-3 text-sm text-muted-foreground">
                  On creation the workspace becomes active, the owner becomes its Admin, and the
                  access above is granted. Creating counts against your plan&apos;s workspace limit.
                </p>
                {submitError ? (
                  <p role="alert" className="text-sm text-status-danger">
                    {describeError(submitError)}
                  </p>
                ) : null}
                <div className="flex justify-between pt-2">
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => setStep(1)}
                    disabled={submitting}
                  >
                    Back
                  </Button>
                  <Button type="button" onClick={submit} disabled={submitting}>
                    {submitting ? "Creating…" : "Create workspace"}
                  </Button>
                </div>
              </div>
            ) : null}
          </CardContent>
        </Card>
        <Card className="h-fit">
          <CardHeader>
            <CardTitle>Summary</CardTitle>
            <CardDescription>Entered so far</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="space-y-2 text-sm">
              <div>
                <dt className="text-muted-foreground">Name</dt>
                <dd className="break-words">{details.name || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Owner</dt>
                <dd>{owner?.label ?? "You"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Business unit</dt>
                <dd>{details.businessUnit || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Access grants</dt>
                <dd>{rows.length}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      </div>
    </AppPageLayout>
  );
}
