import { useListParams } from "@/hooks/use-page-list.js";
import { Plus, Workflow } from "lucide-react";
import { LinkButton } from "@/components/common/link-button.jsx";
import { EmptyState } from "@/components/states/empty-state.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { DisabledWithReason } from "@/features/authorization/components/permission-gate.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import { usePipelineOptions, useRepositoryPipelines } from "../hooks/use-pipelines.js";
import { PipelineTable } from "./pipeline-table.jsx";

/**
 * Why "Add pipeline" cannot be used now, or null (SCREENS §3 change 3): the repository must be active and enabled, and the
 * plan limit (`options.pipelines`) must not be reached. `limit` 0 means the plan has no pipelines entitlement.
 */
export function addPipelineReason(repository, options) {
  if (repository.status !== "active" || !repository.enabled)
    return "Pipelines can be created once the repository is active.";
  const quota = options?.pipelines;
  if (quota && quota.limit !== null && quota.limit !== undefined && quota.used >= quota.limit)
    return quota.limit === 0
      ? "Your plan does not include pipelines."
      : `Your plan limit of ${quota.limit} pipelines is reached.`;
  return null;
}

/** The "Add pipeline" header action (the page's only mint button). Hidden without `pipeline.manage`. */
export function AddPipelineButton({ repository, variant = "default" }) {
  const can = useCan();
  const scope = { type: "workspace", workspaceId: repository.workspaceId };
  const manage = can("pipeline.manage", scope);
  const options = usePipelineOptions(repository.workspaceId, { enabled: manage });
  if (!manage) return null;
  const reason = addPipelineReason(repository, options.data);
  return (
    <DisabledWithReason reason={reason}>
      <LinkButton
        variant={variant}
        to={`/workspaces/${repository.workspaceId}/pipelines/new?repository=${repository.id}`}
      >
        <Plus aria-hidden="true" />
        Add pipeline
      </LinkButton>
    </DisabledWithReason>
  );
}

/** Pipelines tab of T-24: compact table of the repository's pipelines. */
export function RepositoryPipelinesTab({ repository }) {
  const { page, pageSize, setPage, setPageSize } = useListParams();
  const query = useRepositoryPipelines(
    repository.id,
    { sort: "name:asc" },
    { page, pageSize, setPage },
  );
  const can = useCan();
  const manage = can("pipeline.manage", { type: "workspace", workspaceId: repository.workspaceId });
  if (query.isPending) return <LoadingState rows={4} label="Loading pipelines" />;
  if (query.isError) return <QueryErrorState error={query.error} onRetry={query.refetch} />;
  if (query.data.items.length === 0)
    return (
      <EmptyState
        icon={Workflow}
        title="No pipelines on this repository"
        description="A pipeline decides what is scanned and when."
        actions={manage ? <AddPipelineButton repository={repository} variant="secondary" /> : null}
      />
    );
  return (
    <PipelineTable
      caption="Pipelines of this repository"
      items={query.data.items}
      showRepository={false}
      pagination={query.pagination}
      onPage={setPage}
      onPageSize={setPageSize}
    />
  );
}
