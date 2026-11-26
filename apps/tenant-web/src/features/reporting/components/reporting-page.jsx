import { RefreshCw, ShieldOff } from "lucide-react";
import { Link } from "react-router";
import { AppPageLayout } from "@qmentisai/ui";
import { Button } from "@/components/ui/button.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { cn } from "@/lib/cn.js";
import { ANALYSIS_SCREENS } from "../constants/index.js";
import { useReportingRealtime, useReportingRefresh } from "../hooks/use-reporting.js";
import { PeriodControl } from "./period-control.jsx";

/**
 * "Dashboard / Trends" and the links to the other analysis screens the person may open (SCREENS 3). The four analysis screens are
 * NOT sidebar items (SPEC D-2); the permission of each is the engine's (`useCan`), never a role name.
 * @param {{ workspaceId: string, current: string }} props
 */
export function AnalysisNav({ workspaceId, current }) {
  const can = useCan();
  const screens = ANALYSIS_SCREENS.filter((s) => can(s.permission));
  const here = screens.find((s) => s.id === current);
  return (
    <nav aria-label="Breadcrumb" className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
      <ol className="flex items-center gap-1.5 text-muted-foreground">
        <li>
          <Link
            to={`/workspaces/${workspaceId}/dashboard`}
            className="rounded-sm underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
          >
            Dashboard
          </Link>
        </li>
        {current !== "dashboard" && here ? (
          <>
            <li aria-hidden="true">/</li>
            <li aria-current="page" className="font-medium text-foreground">
              {here.label}
            </li>
          </>
        ) : null}
      </ol>
      <ul aria-label="Other views" className="flex flex-wrap gap-x-3 text-xs">
        {screens
          .filter((s) => s.id !== current && s.id !== "dashboard")
          .map((s) => (
            <li key={s.id}>
              <Link
                to={`/workspaces/${workspaceId}/${s.path}`}
                className="rounded-sm text-primary-text underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
              >
                {s.label}
              </Link>
            </li>
          ))}
      </ul>
    </nav>
  );
}

/** "Some sections are not available to you" (SCREENS 1, partial). @param {{ sections: string[] }} props */
export function PartialNotice({ sections }) {
  if (!sections.length) return null;
  return (
    <p
      role="status"
      className="mb-4 flex items-start gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm text-muted-foreground"
    >
      <ShieldOff aria-hidden="true" className="mt-0.5 size-4 shrink-0" />
      <span>Some sections are not available to you: {sections.join(", ")}.</span>
    </p>
  );
}

/** The Refresh icon button: a manual refetch always works (SPEC D-4). */
export function RefreshButton({ workspaceId }) {
  const { refresh, fetching } = useReportingRefresh(workspaceId);
  return (
    <Button
      variant="secondary"
      size="icon"
      aria-label="Refresh"
      title="Refresh"
      onClick={() => refresh()}
    >
      <RefreshCw
        aria-hidden="true"
        className={cn(fetching && "animate-spin motion-reduce:animate-none")}
      />
    </Button>
  );
}

/**
 * The frame of the workspace reporting screens: title, the analysis breadcrumb, Refresh, the shared period control, and the
 * realtime join (the existing findings room). `children` render below the controls.
 * @param {{ workspaceId: string, current: string, title: string, description?: string, params: any, timeZone?: string,
 *   showPeriod?: boolean, actions?: import("react").ReactNode, controls?: import("react").ReactNode, hiddenSections?: string[], children: any }} props
 */
export function ReportingPage({
  workspaceId,
  current,
  title,
  description,
  params,
  timeZone,
  showPeriod = true,
  actions,
  controls,
  hiddenSections = [],
  children,
}) {
  useReportingRealtime(workspaceId);
  return (
    <AppPageLayout
      title={title}
      description={description}
      breadcrumb={<AnalysisNav workspaceId={workspaceId} current={current} />}
      actions={
        <>
          {actions}
          <RefreshButton workspaceId={workspaceId} />
        </>
      }
    >
      <div className="mb-4 flex flex-wrap items-start justify-between gap-4 print:hidden">
        {showPeriod ? <PeriodControl params={params} timeZone={timeZone} /> : <span />}
        {controls}
      </div>
      <PartialNotice sections={hiddenSections} />
      {children}
    </AppPageLayout>
  );
}
