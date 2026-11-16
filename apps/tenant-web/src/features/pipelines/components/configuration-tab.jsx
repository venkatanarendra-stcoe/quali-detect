import { useSearchParams } from "react-router";
import { QueryTable } from "@/components/common/query-table.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { usePipelineVersion, usePipelineVersions } from "../hooks/use-pipelines.js";
import { ConfigDiff, ConfigView } from "./config-view.jsx";
import { Identifier, TimeAgo } from "@/features/executions/components/execution-bits.jsx";

/** Version summary of a list row: `changeSummary` is a list of PATHS only (never values). */
function summaryText(s) {
  const parts = [];
  if (s?.added?.length) parts.push(`${s.added.length} added`);
  if (s?.changed?.length) parts.push(`${s.changed.length} changed`);
  if (s?.removed?.length) parts.push(`${s.removed.length} removed`);
  return parts.length ? parts.join(", ") : "—";
}

/** Columns of the versions table; clicking a version number selects it (`update({ version })`). */
function versionColumns(currentVersion, update) {
  return [
    {
      id: "version",
      header: "Version",
      cell: ({ row: { original: v } }) => (
        <>
          <button
            type="button"
            onClick={() =>
              update({ version: v.version === currentVersion ? "" : String(v.version) })
            }
            className="rounded-sm underline-offset-2 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
          >
            {v.version}
          </button>
          {v.version === currentVersion ? (
            <span className="ml-1 text-xs text-muted-foreground">current</span>
          ) : null}
        </>
      ),
    },
    {
      id: "published",
      header: "Published",
      cell: ({ row: { original: v } }) => <TimeAgo value={v.createdAt} />,
    },
    { id: "by", header: "By", cell: ({ row: { original: v } }) => v.createdBy?.name ?? "—" },
    {
      id: "note",
      header: "Note",
      meta: { className: "max-w-56 break-words" },
      cell: ({ row: { original: v } }) => v.changeNote ?? "—",
    },
    {
      id: "changes",
      header: "Changes",
      cell: ({ row: { original: v } }) => summaryText(v.changeSummary),
    },
    {
      id: "hash",
      header: "Hash",
      cell: ({ row: { original: v } }) => <Identifier value={v.configHash} max={6} />,
    },
  ];
}

function VersionDetail({ pipelineId, version }) {
  const current = usePipelineVersion(pipelineId, version);
  const previous = usePipelineVersion(pipelineId, version - 1, { enabled: version > 1 });
  if (current.isPending) return <LoadingState rows={4} label="Loading version" />;
  if (current.isError) return <QueryErrorState error={current.error} onRetry={current.refetch} />;
  const v = current.data;
  return (
    <div className="space-y-5">
      <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-2">
        <div>
          <dt className="text-muted-foreground">Version</dt>
          <dd>{v.version} (immutable)</dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Hash</dt>
          <dd>
            <Identifier value={v.configHash} max={8} copy label="configuration hash" />
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Published</dt>
          <dd>
            <TimeAgo value={v.createdAt} />
            {v.createdBy?.name ? ` by ${v.createdBy.name}` : ""}
          </dd>
        </div>
        <div>
          <dt className="text-muted-foreground">Change note</dt>
          <dd>{v.changeNote ?? "—"}</dd>
        </div>
      </dl>
      {version > 1 ? (
        previous.isPending ? (
          <LoadingState rows={2} label="Loading the previous version" />
        ) : previous.isError ? (
          <QueryErrorState error={previous.error} onRetry={previous.refetch} />
        ) : (
          <ConfigDiff
            title={`Compared with version ${version - 1}`}
            previous={previous.data.config}
            next={v.config}
          />
        )
      ) : (
        <p className="text-sm text-muted-foreground">
          This is the first version, so there is nothing to compare with.
        </p>
      )}
      <ConfigView config={v.config} />
    </div>
  );
}

/** Configuration tab of T-27: version selector, diff against the previous version, the version list. Editing opens the wizard. */
export function ConfigurationTab({ pipeline }) {
  const [params, setParams] = useSearchParams();
  const currentVersion = pipeline.currentVersion?.version ?? 1;
  const selected = Number(params.get("version")) || currentVersion;
  const page = Math.max(1, Number(params.get("vpage")) || 1);
  const versions = usePipelineVersions(pipeline.id, { page, pageSize: 10 });
  const update = (next) =>
    setParams(
      (cur) => {
        const merged = new URLSearchParams(cur);
        for (const [k, v] of Object.entries(next)) v ? merged.set(k, v) : merged.delete(k);
        return merged;
      },
      { replace: true },
    );
  const choices = versions.data?.items.map((v) => v.version) ?? [];
  if (!choices.includes(selected)) choices.unshift(selected);
  return (
    <div className="space-y-6">
      <div className="max-w-xs space-y-1.5">
        <Label htmlFor="cfg-version">Version</Label>
        <Select
          id="cfg-version"
          value={String(selected)}
          onChange={(e) =>
            update({ version: e.target.value === String(currentVersion) ? "" : e.target.value })
          }
        >
          {choices.map((n) => (
            <option key={n} value={n}>
              Version {n}
              {n === currentVersion ? " (current)" : ""}
            </option>
          ))}
        </Select>
      </div>
      <VersionDetail key={selected} pipelineId={pipeline.id} version={selected} />
      <section aria-labelledby="versions-h">
        <h3 id="versions-h" className="mb-2 text-sm font-semibold">
          Versions
        </h3>
        <p className="mb-2 text-xs text-muted-foreground">
          Versions are immutable. Editing the configuration publishes a new version; requests
          already made keep the version they were made with.
        </p>
        <QueryTable
          caption="Configuration versions"
          query={versions}
          columns={versionColumns(currentVersion, update)}
          getRowId={(v) => String(v.version)}
          height="auto"
          maxHeight="22rem"
          pagination={versions.data?.pagination}
          onPage={(p) => update({ vpage: p > 1 ? String(p) : "" })}
        />
      </section>
    </div>
  );
}
