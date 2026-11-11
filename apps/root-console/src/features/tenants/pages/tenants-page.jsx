import { Building2, SearchX } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { PageHeader } from "@/components/common/page-header.jsx";
import { Pager } from "@/components/common/pager.jsx";
import { SortHeader } from "@/components/common/sort-header.jsx";
import { TenantStatusChip } from "@/components/common/tenant-status-chip.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { LinkButton } from "@/components/common/link-button.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { PlatformPermissionGate, useCanPlatform } from "@/features/authorization/index.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { usePlans, useTenantList } from "../hooks/use-tenants.js";

const PAGE_SIZE = 20;
const date = (value) =>
  new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

/**
 * R-04 Tenants: metadata and counts only (never tenant content). Search, status and plan filters, sorting and the page
 * live in the URL. Provisioning needs `platform.tenant.create`.
 */
export function TenantsPage() {
  const can = useCanPlatform();
  const [params, setParams] = useSearchParams();
  const qParam = params.get("q") ?? "";
  const status = params.get("status") ?? "";
  const plan = params.get("plan") ?? "";
  const sort = params.get("sort") ?? "name:asc";
  const page = Math.max(1, Number(params.get("page")) || 1);
  const [search, setSearch] = useState(qParam);
  const debounced = useDebouncedValue(search);
  const filtered = Boolean(qParam || status || plan);

  const update = (next) =>
    setParams(
      (current) => {
        const merged = new URLSearchParams(current);
        for (const [key, value] of Object.entries(next))
          value ? merged.set(key, value) : merged.delete(key);
        return merged;
      },
      { replace: true },
    );
  useEffect(() => {
    if (debounced.trim() !== qParam) update({ q: debounced.trim(), page: "" });
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the debounced text drives the URL
  }, [debounced]);

  const plans = usePlans({ enabled: can("platform.plan.view") });
  const planOptions = [
    ...new Map((plans.data ?? []).map((p) => [p.planKey, p.planName])).entries(),
  ];
  const list = useTenantList({
    q: qParam || undefined,
    status: status || undefined,
    plan: plan || undefined,
    sort,
    page,
    pageSize: PAGE_SIZE,
  });
  const clear = () => {
    setSearch("");
    setParams({}, { replace: true });
  };

  return (
    <>
      <PageHeader
        title="Tenant management"
        description="Customer organizations on the platform."
        actions={
          <PlatformPermissionGate
            permission="platform.tenant.create"
            mode="disable"
            reason="You need the platform.tenant.create permission to provision tenants."
          >
            <LinkButton to="/tenants/new">Provision tenant</LinkButton>
          </PlatformPermissionGate>
        }
      />
      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div className="w-full max-w-xs">
          <label htmlFor="tenant-search" className="sr-only">
            Search tenants
          </label>
          <Input
            id="tenant-search"
            type="search"
            placeholder="Search by name or slug"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="w-40">
          <label htmlFor="tenant-status" className="sr-only">
            Status
          </label>
          <Select
            id="tenant-status"
            value={status}
            onChange={(e) => update({ status: e.target.value, page: "" })}
          >
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="trial">Trial</option>
            <option value="suspended">Suspended</option>
            <option value="deactivated">Deactivated</option>
          </Select>
        </div>
        {planOptions.length > 0 ? (
          <div className="w-44">
            <label htmlFor="tenant-plan" className="sr-only">
              Plan
            </label>
            <Select
              id="tenant-plan"
              value={plan}
              onChange={(e) => update({ plan: e.target.value, page: "" })}
            >
              <option value="">All plans</option>
              {planOptions.map(([key, name]) => (
                <option key={key} value={key}>
                  {name}
                </option>
              ))}
            </Select>
          </div>
        ) : null}
        {filtered ? (
          <Button variant="ghost" onClick={clear}>
            Clear filters
          </Button>
        ) : null}
        {list.data?.pagination ? (
          <p className="ml-auto text-sm text-muted-foreground" aria-live="polite">
            {list.data.pagination.totalItems}{" "}
            {list.data.pagination.totalItems === 1 ? "tenant" : "tenants"}
          </p>
        ) : null}
      </div>

      {list.isPending ? <LoadingState label="Loading tenants" /> : null}
      {list.isError ? <QueryErrorState error={list.error} onRetry={list.refetch} /> : null}
      {list.data && list.data.items.length === 0 ? (
        filtered ? (
          <EmptyState
            icon={SearchX}
            title="No matching tenants"
            description="Try different filters."
            actions={
              <Button variant="secondary" onClick={clear}>
                Clear filters
              </Button>
            }
          />
        ) : (
          <EmptyState
            icon={Building2}
            title="No tenants yet"
            description="Provision the first tenant to onboard a customer."
            actions={
              can("platform.tenant.create") ? (
                <Button asChild>
                  <Link to="/tenants/new">Provision tenant</Link>
                </Button>
              ) : null
            }
          />
        )
      ) : null}
      {list.data && list.data.items.length > 0 ? (
        <>
          <div className="overflow-x-auto rounded-md border border-border bg-card">
            <table className="w-full text-left text-[13px] leading-5">
              <caption className="sr-only">Tenants</caption>
              <thead className="border-b border-border text-muted-foreground">
                <tr>
                  <SortHeader
                    label="Tenant"
                    field="name"
                    sort={sort}
                    onSort={(s) => update({ sort: s === "name:asc" ? "" : s, page: "" })}
                  />
                  <SortHeader
                    label="Status"
                    field="status"
                    sort={sort}
                    onSort={(s) => update({ sort: s, page: "" })}
                  />
                  <th scope="col" className="px-3 py-2 font-medium">
                    Plan
                  </th>
                  <th scope="col" className="px-3 py-2 text-right font-medium">
                    Users
                  </th>
                  <th scope="col" className="px-3 py-2 text-right font-medium">
                    Workspaces
                  </th>
                  <SortHeader
                    label="Created"
                    field="createdAt"
                    sort={sort}
                    onSort={(s) => update({ sort: s, page: "" })}
                  />
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((t) => (
                  <tr
                    key={t.id}
                    className="h-9 border-b border-border last:border-0 hover:bg-secondary"
                  >
                    <td className="px-3 py-1.5">
                      <Link
                        className="font-medium text-primary-text underline-offset-4 hover:underline"
                        to={`/tenants/${t.id}`}
                      >
                        {t.name}
                      </Link>
                      <p className="font-mono text-xs text-subtle-foreground">{t.slug}</p>
                    </td>
                    <td className="px-3">
                      <TenantStatusChip status={t.status} />
                    </td>
                    <td className="px-3 text-muted-foreground">
                      {t.plan ? `${t.plan.name} v${t.plan.version}` : "No plan"}
                    </td>
                    <td className="px-3 text-right tabular-nums">{t.userCount}</td>
                    <td className="px-3 text-right tabular-nums">{t.workspaceCount}</td>
                    <td className="px-3 text-muted-foreground">{date(t.createdAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            pagination={list.data.pagination}
            onPage={(p) => update({ page: p > 1 ? String(p) : "" })}
          />
        </>
      ) : null}
    </>
  );
}
