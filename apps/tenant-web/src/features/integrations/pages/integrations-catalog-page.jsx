import { Cable } from "lucide-react";
import { Link, useSearchParams } from "react-router";
import { PageHeader } from "@/components/common/page-header.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import { Card, CardContent } from "@/components/ui/card.jsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.jsx";
import { cn } from "@/lib/cn.js";
import { LinkHealth } from "../components/link-health.jsx";
import { LinkingSetting } from "../components/linking-setting.jsx";
import { SourceControlSection } from "../components/source-control-section.jsx";
import { useCatalog } from "../hooks/use-integrations.js";

const CATEGORIES = [
  ["all", "All"],
  ["source_control", "Source control"],
  ["ai_coding_tools", "AI coding tools"],
  ["ticketing", "Ticketing"],
  ["collaboration", "Collaboration"],
  ["security_tools", "Security tools"],
  ["cloud", "Cloud"],
  ["secrets", "Secrets"],
];

/**
 * T-13 Integrations (organization). Tenant-wide tools are listed with a disabled button and "Not available yet", so the
 * page never implies a capability that does not exist. Source control is connected from a workspace; here it is a
 * read-only section (installations and the workspaces using them) plus the tenant setting that allows workspace linking.
 */
export function IntegrationsCatalogPage() {
  const [params, setParams] = useSearchParams();
  const category = params.get("category") ?? "all";
  const catalog = useCatalog();
  const items = (catalog.data?.items ?? []).filter(
    (i) => i.provider !== "github" && (category === "all" || i.category === category),
  );
  const showSourceControl = category === "all" || category === "source_control";
  return (
    <>
      <PageHeader
        title="Integrations"
        description="Tools connected to this organization. Source control is connected from a workspace's Integrations page."
      />
      <div
        role="tablist"
        aria-label="Categories"
        className="mb-4 flex max-w-full flex-wrap gap-1 border-b border-border"
      >
        {CATEGORIES.map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={category === id}
            onClick={() => setParams(id === "all" ? {} : { category: id }, { replace: true })}
            className={cn(
              "-mb-px border-b-2 px-3 py-2 text-sm",
              category === id
                ? "border-foreground font-medium"
                : "border-transparent text-muted-foreground",
            )}
          >
            {label}
          </button>
        ))}
      </div>
      {showSourceControl ? (
        <section aria-labelledby="source-control-heading" className="mb-8 space-y-3">
          <h2 id="source-control-heading" className="text-base font-semibold">
            Source control
          </h2>
          <LinkingSetting />
          <SourceControlSection />
        </section>
      ) : null}
      {catalog.isPending ? <LoadingState label="Loading integrations" /> : null}
      {catalog.isError ? <QueryErrorState error={catalog.error} onRetry={catalog.refetch} /> : null}
      {items.length > 0 ? (
        <section aria-labelledby="tools-heading" className="space-y-3">
          <h2 id="tools-heading" className="text-base font-semibold">
            Organization tools
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {items.map((item) => (
              <Card key={item.provider}>
                <CardContent className="flex h-full flex-col gap-3 pt-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2">
                      <span
                        className="flex size-8 items-center justify-center rounded-sm border border-border text-muted-foreground"
                        aria-hidden="true"
                      >
                        <Cable className="size-4" />
                      </span>
                      <h3 className="text-sm font-semibold">{item.name}</h3>
                      {item.beta ? <Badge>Beta</Badge> : null}
                    </div>
                    <LinkHealth status={item.status} />
                  </div>
                  <div className="mt-auto">
                    {item.available ? (
                      <Button asChild variant="secondary" size="sm">
                        <Link to={`/integrations/${item.provider}`}>Manage</Link>
                      </Button>
                    ) : (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span
                            role="button"
                            aria-disabled="true"
                            tabIndex={0}
                            className="inline-flex rounded-sm"
                          >
                            <Button
                              size="sm"
                              variant="secondary"
                              disabled
                              aria-label={`${item.name}: not available yet`}
                            >
                              Connect
                            </Button>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent>Not available yet.</TooltipContent>
                      </Tooltip>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </section>
      ) : null}
    </>
  );
}
