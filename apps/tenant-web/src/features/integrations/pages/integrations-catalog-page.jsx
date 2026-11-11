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
 * T-13 Integrations catalog. Only GitHub is live; the other providers are listed with a disabled button and the status
 * "Not available yet", so the page never implies a capability that does not exist (TAD §3.14). Category lives in the URL.
 */
export function IntegrationsCatalogPage() {
  const [params, setParams] = useSearchParams();
  const category = params.get("category") ?? "all";
  const catalog = useCatalog();
  const items = (catalog.data?.items ?? []).filter(
    (i) => category === "all" || i.category === category,
  );
  return (
    <>
      <PageHeader
        title="Integrations"
        description="Connect source control and other tools to this organization."
      />
      <div
        role="tablist"
        aria-label="Categories"
        className="mb-4 flex flex-wrap gap-1 border-b border-border"
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
      {catalog.isPending ? <LoadingState label="Loading integrations" /> : null}
      {catalog.isError ? <QueryErrorState error={catalog.error} onRetry={catalog.refetch} /> : null}
      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((item) => (
          <Card key={item.provider}>
            <CardContent className="flex h-full flex-col gap-3 pt-4">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className="flex size-8 items-center justify-center rounded-sm border border-border text-muted-foreground"
                    aria-hidden="true"
                  >
                    <Cable className="size-4" />
                  </span>
                  <h2 className="text-sm font-semibold">{item.name}</h2>
                  {item.beta ? <Badge>Beta</Badge> : null}
                </div>
                <LinkHealth status={item.status} />
              </div>
              <div className="mt-auto">
                {item.available && item.status !== "not_configured" ? (
                  <Button
                    asChild
                    variant={item.status === "not_connected" ? "default" : "secondary"}
                    size="sm"
                  >
                    <Link to={`/integrations/${item.provider}`}>
                      {item.status === "not_connected" ? "Connect" : "Manage"}
                    </Link>
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
                          aria-label={`${item.name}: ${item.status === "not_configured" ? "not configured by your platform administrator" : "not available yet"}`}
                        >
                          Connect
                        </Button>
                      </span>
                    </TooltipTrigger>
                    <TooltipContent>
                      {item.status === "not_configured"
                        ? "Ask your platform administrator to configure the GitHub App."
                        : "Not available yet."}
                    </TooltipContent>
                  </Tooltip>
                )}
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </>
  );
}
