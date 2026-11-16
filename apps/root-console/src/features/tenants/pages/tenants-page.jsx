import { Building2, SearchX } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { AppPageLayout } from "@qmentisai/ui";
import { Link, useNavigate, useSearchParams } from "react-router";
import { LinkButton } from "@/components/common/link-button.jsx";
import { QueryTable } from "@/components/common/query-table.jsx";
import { TenantStatusChip } from "@/components/common/tenant-status-chip.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Select } from "@/components/ui/select.jsx";
import { PlatformPermissionGate, useCanPlatform } from "@/features/authorization/index.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { usePlans, useTenantList } from "../hooks/use-tenants.js";

const PAGE_SIZE = 20; // rows per "Load more" request
const date = (value) =>
  new Date(value).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });

/**
 * R-04 Tenants: metadata and counts only (never tenant content). Search, status and plan filters, and sorting live in the URL; rows load with "Load more" (cursor), no totals are shown. Provisioning needs `platform.tenant.create`.
 */
export function TenantsPage() {
  const can = useCanPlatform();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const qParam = params.get("q") ?? "";
  const status = params.get("status") ?? "";
  const plan = params.get("plan") ?? "";
  const sort = params.get("sort") ?? "name:asc";
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
    if (debounced.trim() !== qParam) update({ q: debounced.trim() });
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
    limit: PAGE_SIZE,
  });
  const clear = () => {
    setSearch("");
    setParams({}, { replace: true });
  };
  const columns = useMemo(
    () => [
      {
        id: "name",
        accessorKey: "name",
        header: "Tenant",
        sortDescFirst: false,
        cell: ({ row: { original: t } }) => (
          <>
            <Link
              className="font-medium text-primary-text underline-offset-4 hover:underline"
              to={`/tenants/${t.id}`}
            >
              {t.name}
            </Link>
            <p className="font-mono text-xs text-subtle-foreground">{t.slug}</p>
          </>
        ),
      },
      {
        id: "status",
        accessorKey: "status",
        header: "Status",
        sortDescFirst: false,
        cell: ({ row: { original: t } }) => <TenantStatusChip status={t.status} />,
      },
      {
        id: "plan",
        header: "Plan",
        enableSorting: false,
        meta: { className: "text-muted-foreground" },
        cell: ({ row: { original: t } }) =>
          t.plan ? `${t.plan.name} v${t.plan.version}` : "No plan",
      },
      {
        id: "users",
        header: () => <span className="block text-right">Users</span>,
        enableSorting: false,
        meta: { className: "text-right tabular-nums" },
        cell: ({ row: { original: t } }) => t.userCount,
      },
      {
        id: "workspaces",
        header: () => <span className="block text-right">Workspaces</span>,
        enableSorting: false,
        meta: { className: "text-right tabular-nums" },
        cell: ({ row: { original: t } }) => t.workspaceCount,
      },
      {
        id: "createdAt",
        accessorKey: "createdAt",
        header: "Created",
        sortDescFirst: false,
        meta: { className: "text-muted-foreground" },
        cell: ({ row: { original: t } }) => date(t.createdAt),
      },
    ],
    [],
  );

  return (
    <AppPageLayout
      title="Tenant management"
      description="Customer organizations on the platform."
      scroll={false}
      offset="4.5rem"
      actions={
        <PlatformPermissionGate
          permission="platform.tenant.create"
          mode="disable"
          reason="You need the platform.tenant.create permission to provision tenants."
        >
          <LinkButton to="/tenants/new">Provision tenant</LinkButton>
        </PlatformPermissionGate>
      }
    >
      <div className="mb-4 flex shrink-0 flex-wrap items-end gap-3">
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
            onChange={(e) => update({ status: e.target.value })}
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
              onChange={(e) => update({ plan: e.target.value })}
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
      </div>

      <QueryTable
        query={list}
        columns={columns}
        caption="Tenants"
        getRowId={(t) => t.id}
        sort={sort}
        onSort={(s) => update({ sort: s === "name:asc" ? "" : s })}
        hasMore={list.hasMore}
        loadingMore={list.loadingMore}
        onLoadMore={list.loadMore}
        onRowClick={(t) => navigate(`/tenants/${t.id}`)}
        rowLabel={(t) => `Open ${t.name}`}
        emptyState={
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
        }
      />
    </AppPageLayout>
  );
}
