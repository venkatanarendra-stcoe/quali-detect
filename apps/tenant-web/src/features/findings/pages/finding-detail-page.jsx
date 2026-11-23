import { AppPageLayout } from "@qmentisai/ui";
import { ChevronLeft, Info } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { Skeleton } from "@/components/ui/skeleton.jsx";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { absoluteTime } from "@/features/executions/components/execution-bits.jsx";
import { SCAN_TYPE_LABELS } from "../constants/index.js";
import { EvidencePanel } from "../components/code-viewer.jsx";
import { FindingActions } from "../components/finding-actions.jsx";
import {
  Identifier,
  RecurrenceIcon,
  SeverityBadge,
  SlaChip,
  StatusBadge,
  Untrusted,
} from "../components/finding-bits.jsx";
import { CommentsTab, HistoryTab } from "../components/finding-history.jsx";
import { FindingOverview } from "../components/finding-overview.jsx";
import { statusPresentation } from "../constants/index.js";
import { useBindMockActor, useFinding, useFindingComments } from "../hooks/use-findings.js";

const TABS = ["overview", "evidence", "history", "comments"];

function DetailSkeleton() {
  return (
    <div role="status" aria-busy="true" className="space-y-4">
      <span className="sr-only">Loading finding…</span>
      <Skeleton className="h-7 w-2/3" />
      <Skeleton className="h-5 w-1/2" />
      <Skeleton className="h-9 w-72" />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_20rem]">
        <Skeleton className="h-64 w-full" />
        <Skeleton className="h-64 w-full" />
      </div>
    </div>
  );
}

function Banner({ children }) {
  return (
    <p className="flex items-center gap-1.5 rounded-md border border-border bg-secondary px-3 py-2 text-sm">
      <Info aria-hidden="true" className="size-4 shrink-0 text-muted-foreground" />
      {children}
    </p>
  );
}

/** Pipeline or repository chip: a link when the caller can open it, plain text otherwise. */
function Chip({ to, children }) {
  const cls =
    "inline-flex items-center rounded-sm border border-border-strong px-1.5 py-0.5 text-xs";
  return to ? (
    <Link
      to={to}
      className={`${cls} underline-offset-2 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring`}
    >
      {children}
    </Link>
  ) : (
    <span className={cls}>{children}</span>
  );
}

function DetailHeaderMeta({ finding, workspaceId }) {
  const can = useCan();
  const tools = finding.provenance.tools.map((t) => t.displayName).join(", ");
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-sm text-muted-foreground">
      <span className="inline-flex items-center gap-1">
        <span className="sr-only">Fingerprint</span>
        <Identifier
          value={finding.fingerprint.slice(0, 16)}
          full={finding.fingerprint}
          copy
          label="fingerprint"
          max={20}
        />
      </span>
      <Chip
        to={
          can("pipeline.view")
            ? `/workspaces/${workspaceId}/pipelines/${finding.pipeline.id}`
            : null
        }
      >
        {finding.pipeline.name}
      </Chip>
      <Chip
        to={
          can("repository.view")
            ? `/workspaces/${workspaceId}/repositories/${finding.repository.id}`
            : null
        }
      >
        {finding.repository.fullName}
      </Chip>
      <span>{SCAN_TYPE_LABELS[finding.scanType]}</span>
      <Identifier value={finding.ruleId} max={26} label="rule id" />
      {finding.cwe.length ? (
        <span className="font-mono text-xs">{finding.cwe.map((c) => `CWE-${c}`).join(", ")}</span>
      ) : null}
      {tools ? <span>Detected by {tools}</span> : null}
    </div>
  );
}

function Banners({ finding }) {
  return (
    <div className="space-y-2 empty:hidden">
      {finding.pipeline.deleted ? <Banner>Pipeline deleted. Verification is paused.</Banner> : null}
      {finding.coverage.notScannedRecently ? (
        <Banner>Not scanned recently: this scan type is no longer enabled.</Banner>
      ) : null}
      {finding.status === "accepted_risk" && finding.exception?.expiresAt ? (
        <Banner>
          Accepted risk until {absoluteTime(finding.exception.expiresAt, { dateStyle: "medium" })}
        </Banner>
      ) : null}
      {finding.exception?.state === "pending" ? (
        <Banner>
          {finding.exception.kind === "suppress" ? "Suppression" : "Accepted risk"} requested by{" "}
          {finding.exception.requestedBy.displayName}, waiting for approval
        </Banner>
      ) : null}
    </div>
  );
}

/**
 * T-32 Finding detail: header, banners, actions from the DTO and the tabs Overview, Evidence, History and Comments (URL `tab`).
 * A finding in another workspace, another tenant or nonexistent is the same not-found page (the API answers 404).
 */
export function FindingDetailPage() {
  const { workspaceId, findingId } = useParams();
  useBindMockActor(workspaceId);
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const tab = TABS.includes(params.get("tab")) ? params.get("tab") : "overview";
  const query = useFinding(workspaceId, findingId);
  const comments = useFindingComments(workspaceId, findingId);
  const finding = query.data;
  const back = `/workspaces/${workspaceId}/findings${location.state?.list ?? ""}`;

  // announce a status change that happens while the page is open (polite, once)
  const previous = useRef(null);
  const [announcement, setAnnouncement] = useState("");
  useEffect(() => {
    if (!finding) return;
    if (previous.current && previous.current !== finding.status)
      setAnnouncement(`Status changed to ${statusPresentation(finding.status).label}.`);
    previous.current = finding.status;
  }, [finding]);

  const commentCount = comments.data?.items.length;
  const commentLabel =
    typeof commentCount === "number"
      ? `Comments (${commentCount}${comments.hasMore ? "+" : ""})`
      : "Comments";

  return (
    <AppPageLayout
      title={finding ? <Untrusted>{finding.title}</Untrusted> : "Finding"}
      breadcrumb={
        <nav aria-label="Breadcrumb">
          <Link
            to={back}
            className="inline-flex items-center gap-1 rounded-sm text-sm text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
          >
            <ChevronLeft aria-hidden="true" className="size-4" />
            Findings
          </Link>
        </nav>
      }
      actions={
        finding ? (
          <FindingActions
            workspaceId={workspaceId}
            finding={finding}
            onReload={() => query.refetch()}
          />
        ) : null
      }
    >
      <div className="sr-only" role="status" aria-live="polite">
        {announcement}
      </div>
      {query.isPending ? <DetailSkeleton /> : null}
      {query.isError ? <QueryErrorState error={query.error} onRetry={query.refetch} /> : null}
      {finding ? (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            <StatusBadge
              status={finding.status}
              detail={
                finding.status === "awaiting_approval" && finding.review.current
                  ? `pending ${finding.review.current.decision === "false_positive" ? "FP" : "TP"} decision`
                  : finding.status === "accepted_risk" && finding.exception?.expiresAt
                    ? `until ${absoluteTime(finding.exception.expiresAt, { dateStyle: "medium" })}`
                    : undefined
              }
              by={finding.status === "in_review" ? finding.claimedBy?.displayName : null}
            />
            <SlaChip sla={finding.sla} />
            <RecurrenceIcon count={finding.reopenCount} />
          </div>
          <DetailHeaderMeta finding={finding} workspaceId={workspaceId} />
          <Banners finding={finding} />
          <Tabs
            value={tab}
            onValueChange={(v) =>
              setParams(
                (p) => {
                  const n = new URLSearchParams(p);
                  if (v === "overview") n.delete("tab");
                  else n.set("tab", v);
                  return n;
                },
                { replace: true },
              )
            }
          >
            <TabsList aria-label="Finding sections">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="evidence">Evidence</TabsTrigger>
              <TabsTrigger value="history">History</TabsTrigger>
              <TabsTrigger value="comments">{commentLabel}</TabsTrigger>
            </TabsList>
            <TabsContent value="overview">
              <FindingOverview
                workspaceId={workspaceId}
                finding={finding}
                onReload={() => query.refetch()}
              />
            </TabsContent>
            <TabsContent value="evidence">
              <EvidencePanel finding={finding} />
            </TabsContent>
            <TabsContent value="history">
              <HistoryTab workspaceId={workspaceId} findingId={finding.id} />
            </TabsContent>
            <TabsContent value="comments">
              <CommentsTab workspaceId={workspaceId} findingId={finding.id} />
            </TabsContent>
          </Tabs>
        </div>
      ) : null}
    </AppPageLayout>
  );
}
