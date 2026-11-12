import { Link } from "react-router";
import { SortHeader } from "@/components/common/sort-header.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { usePipelineConfigs } from "../hooks/use-pipelines.js";
import { PipelineEnabledSwitch, PipelineRowActions } from "./pipeline-actions.jsx";
import { EffectiveStateChip, LastRequest, ScanChips, TriggerChips } from "./pipeline-bits.jsx";

/**
 * Pipelines table of T-25 (full) and the T-24 tab (compact: no repository column). `sort` / `onSort` are optional: without
 * them the headers are plain text. Row actions follow the caller's permissions (hidden or disabled with a reason).
 * @param {{ items: any[], showRepository?: boolean, sort?: string, onSort?: (next: string) => void, caption: string }} props
 */
export function PipelineTable({ items, showRepository = true, sort, onSort, caption }) {
  const configs = usePipelineConfigs(items.filter((p) => !p.deletedAt));
  const plain = (label) => (
    <th scope="col" className="px-3 py-2 font-medium">
      {label}
    </th>
  );
  return (
    <div className="relative overflow-x-auto rounded-md border border-border bg-card">
      <table className="w-full text-left text-[13px] leading-5">
        <caption className="sr-only">{caption}</caption>
        <thead className="border-b border-border text-muted-foreground">
          <tr>
            {onSort ? (
              <SortHeader label="Pipeline" field="name" sort={sort} onSort={onSort} />
            ) : (
              plain("Pipeline")
            )}
            {showRepository ? plain("Repository") : null}
            {plain("Triggers")}
            {plain("Scans")}
            {onSort ? (
              <SortHeader
                label="Last request"
                field="lastRequestedAt"
                sort={sort}
                onSort={onSort}
              />
            ) : (
              plain("Last request")
            )}
            {plain("State")}
            {plain("Enabled")}
            <th scope="col" className="px-3 py-2 text-right font-medium">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((p) => (
            <tr key={p.id} className="border-b border-border align-top last:border-0">
              <td className="max-w-64 px-3 py-2">
                <Link
                  className="font-medium underline-offset-2 hover:underline focus-visible:underline"
                  to={`/workspaces/${p.workspaceId}/pipelines/${p.id}`}
                >
                  {p.name}
                </Link>
                {p.deletedAt ? (
                  <Badge tone="neutral" className="ml-2">
                    Deleted
                  </Badge>
                ) : null}
                {p.description ? (
                  <div className="truncate text-xs text-muted-foreground">{p.description}</div>
                ) : null}
              </td>
              {showRepository ? (
                <td className="px-3 py-2">
                  {p.repository.name ? (
                    <span className="font-mono text-xs break-all">{p.repository.name}</span>
                  ) : (
                    <span className="text-muted-foreground">Not shown</span>
                  )}
                </td>
              ) : null}
              <td className="px-3 py-2">
                <TriggerChips pipeline={p} config={configs.get(p.id)} />
              </td>
              <td className="px-3 py-2">
                <ScanChips config={p.deletedAt ? null : configs.get(p.id)} />
              </td>
              <td className="px-3 py-2">
                <LastRequest lastRequest={p.lastRequest} />
              </td>
              <td className="px-3 py-2">
                <EffectiveStateChip state={p.effectiveState} />
              </td>
              <td className="px-3 py-2">
                <PipelineEnabledSwitch pipeline={p} />
              </td>
              <td className="px-3 py-2 text-right">
                <PipelineRowActions pipeline={p} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
