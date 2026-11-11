import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { Link, useNavigate } from "react-router";
import { toast } from "sonner";
import { z } from "zod";
import { PageHeader } from "@/components/common/page-header.jsx";
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
import { Select } from "@/components/ui/select.jsx";
import { useCanPlatform } from "@/features/authorization/index.js";
import { describeError } from "@/lib/api/index.js";
import { applyServerIssues } from "@/lib/forms.js";
import { usePlans, useProvisionTenant } from "../hooks/use-tenants.js";

const schema = z.object({
  name: z.string().trim().min(1, "Enter the tenant name.").max(120, "Use at most 120 characters."),
  slug: z
    .string()
    .trim()
    .toLowerCase()
    .regex(
      /^[a-z0-9][a-z0-9-]{1,38}[a-z0-9]$/,
      "Use 3-40 lowercase letters, digits or hyphens (no leading or trailing hyphen).",
    ),
  status: z.enum(["trial", "active"]),
  planVersionId: z.string(),
  adminName: z.string().trim().min(1, "Enter the administrator's name.").max(120),
  adminEmail: z
    .string()
    .trim()
    .min(1, "Enter the administrator's email.")
    .email("Enter a valid email address."),
});
const slugify = (name) =>
  name
    .toLowerCase()
    .normalize("NFKD")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);

/**
 * R-05 Provision tenant: name, slug, initial status, optional plan, and the first administrator. The administrator is
 * INVITED and gets access only after accepting. Plan names come from the API (they are placeholders until defined).
 */
export function ProvisionTenantPage() {
  const navigate = useNavigate();
  const can = useCanPlatform();
  const provision = useProvisionTenant();
  const plans = usePlans({ enabled: can("platform.plan.view") });
  const [slugEdited, setSlugEdited] = useState(false);
  const [formError, setFormError] = useState(null);
  const {
    register,
    handleSubmit,
    setValue,
    setError,
    control,
    formState: { errors },
  } = useForm({
    resolver: zodResolver(schema),
    defaultValues: {
      name: "",
      slug: "",
      status: "trial",
      planVersionId: "",
      adminName: "",
      adminEmail: "",
    },
  });
  const values = useWatch({ control });
  const planLabel = plans.data?.find((p) => p.planVersionId === values.planVersionId);

  const nameField = register("name");
  const onSubmit = handleSubmit(async (v) => {
    setFormError(null);
    try {
      const detail = await provision.mutateAsync({
        name: v.name,
        slug: v.slug,
        status: v.status,
        ...(v.planVersionId ? { planVersionId: v.planVersionId } : {}),
        admin: { name: v.adminName, email: v.adminEmail },
      });
      toast.success(`Tenant "${detail.tenant.name}" provisioned`);
      navigate(`/tenants/${detail.tenant.id}`, { replace: true });
    } catch (error) {
      const fieldMap = {
        slug: "slug",
        name: "name",
        "admin.email": "adminEmail",
        "admin.name": "adminName",
        planVersionId: "planVersionId",
      };
      if (error?.status === 409 && error.details?.field === "slug")
        setError("slug", { message: "This slug is already taken." });
      else if (
        !applyServerIssues(
          error,
          (path, e) => setError(fieldMap[path] ?? "name", e),
          (path) => path in fieldMap,
        )
      )
        setFormError(error);
    }
  });

  return (
    <>
      <PageHeader
        title="Provision tenant"
        description="Create a customer organization and invite its first administrator."
      />
      <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <form onSubmit={onSubmit} noValidate className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Tenant</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-1.5">
                <Label htmlFor="t-name">Name</Label>
                <Input
                  id="t-name"
                  aria-invalid={Boolean(errors.name)}
                  aria-describedby={errors.name ? "t-name-error" : undefined}
                  {...nameField}
                  onChange={(e) => {
                    nameField.onChange(e);
                    if (!slugEdited)
                      setValue("slug", slugify(e.target.value), { shouldValidate: false });
                  }}
                />
                {errors.name ? (
                  <p id="t-name-error" role="alert" className="text-xs text-status-danger">
                    {errors.name.message}
                  </p>
                ) : null}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="t-slug">Slug</Label>
                <Input
                  id="t-slug"
                  className="font-mono"
                  spellCheck={false}
                  aria-invalid={Boolean(errors.slug)}
                  aria-describedby="t-slug-hint"
                  {...register("slug", { onChange: () => setSlugEdited(true) })}
                />
                {errors.slug ? (
                  <p role="alert" className="text-xs text-status-danger">
                    {errors.slug.message}
                  </p>
                ) : (
                  <p id="t-slug-hint" className="text-xs text-subtle-foreground">
                    Unique, lowercase, used in identifiers. It cannot be changed later.
                  </p>
                )}
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="t-status">Initial status</Label>
                  <Select id="t-status" {...register("status")}>
                    <option value="trial">Trial</option>
                    <option value="active">Active</option>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="t-plan">
                    Plan <span className="font-normal text-muted-foreground">(optional)</span>
                  </Label>
                  <Select
                    id="t-plan"
                    disabled={plans.isPending && can("platform.plan.view")}
                    {...register("planVersionId")}
                  >
                    <option value="">No plan</option>
                    {(plans.data ?? []).map((p) => (
                      <option key={p.planVersionId} value={p.planVersionId}>
                        {p.planName} (v{p.version})
                      </option>
                    ))}
                  </Select>
                  {errors.planVersionId ? (
                    <p role="alert" className="text-xs text-status-danger">
                      {errors.planVersionId.message}
                    </p>
                  ) : null}
                  {plans.isError ? (
                    <p role="alert" className="text-xs text-status-danger">
                      {describeError(plans.error)}
                    </p>
                  ) : null}
                  {plans.isSuccess && plans.data.length === 0 ? (
                    <p className="text-xs text-subtle-foreground">
                      No published plans exist yet; the tenant can be given one later.
                    </p>
                  ) : null}
                  {!can("platform.plan.view") ? (
                    <p className="text-xs text-subtle-foreground">
                      Plans are hidden: your role lacks platform.plan.view.
                    </p>
                  ) : null}
                </div>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>First administrator</CardTitle>
              <CardDescription>
                They are invited and get access only after they accept the invitation.
              </CardDescription>
            </CardHeader>
            <CardContent className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="a-name">Name</Label>
                <Input
                  id="a-name"
                  autoComplete="off"
                  aria-invalid={Boolean(errors.adminName)}
                  {...register("adminName")}
                />
                {errors.adminName ? (
                  <p role="alert" className="text-xs text-status-danger">
                    {errors.adminName.message}
                  </p>
                ) : null}
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="a-email">Email</Label>
                <Input
                  id="a-email"
                  type="email"
                  autoComplete="off"
                  aria-invalid={Boolean(errors.adminEmail)}
                  {...register("adminEmail")}
                />
                {errors.adminEmail ? (
                  <p role="alert" className="text-xs text-status-danger">
                    {errors.adminEmail.message}
                  </p>
                ) : null}
              </div>
            </CardContent>
          </Card>
          {formError ? (
            <p role="alert" className="text-sm text-status-danger">
              {describeError(formError)}
            </p>
          ) : null}
          <div className="flex gap-2">
            <Button type="submit" disabled={provision.isPending}>
              {provision.isPending ? "Provisioning…" : "Provision tenant"}
            </Button>
            <Button type="button" variant="ghost" asChild>
              <Link to="/tenants">Cancel</Link>
            </Button>
          </div>
        </form>
        <Card className="h-fit">
          <CardHeader>
            <CardTitle>Summary</CardTitle>
            <CardDescription>Entered so far</CardDescription>
          </CardHeader>
          <CardContent>
            <dl className="space-y-2 text-sm">
              <div>
                <dt className="text-muted-foreground">Name</dt>
                <dd className="break-words">{values.name || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Slug</dt>
                <dd className="font-mono break-all">{values.slug || "—"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Status</dt>
                <dd>{values.status === "active" ? "Active" : "Trial"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Plan</dt>
                <dd>{planLabel ? `${planLabel.planName} (v${planLabel.version})` : "No plan"}</dd>
              </div>
              <div>
                <dt className="text-muted-foreground">First administrator</dt>
                <dd className="break-words">
                  {values.adminName || "—"}
                  <br />
                  <span className="text-muted-foreground">{values.adminEmail}</span>
                </dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
