import { zodResolver } from "@hookform/resolvers/zod";
import { canonicalJson, checkEnableable } from "@qmentisai/shared";
import { useQuery } from "@tanstack/react-query";
import { CircleAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useForm, useWatch } from "react-hook-form";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { toast } from "sonner";
import { ConfirmDialog } from "@/components/common/confirm-dialog.jsx";
import { PageHeader } from "@/components/common/page-header.jsx";
import { QueryErrorState } from "@/components/states/error-state.jsx";
import { LoadingState } from "@/components/states/loading-state.jsx";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import { Button } from "@/components/ui/button.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  useRepository,
  useRepositoryList,
} from "@/features/repositories/hooks/use-repositories.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import { useTenantId } from "@/features/auth/hooks/use-session.js";
import { DryRunDialog } from "../components/dry-run-dialog.jsx";
import { ReviewStep } from "../components/wizard-review.jsx";
import { BasicsStep, ControlsStep, ScansStep } from "../components/wizard-steps.jsx";
import { WizardSummary } from "../components/wizard-summary.jsx";
import { TriggersStep } from "../components/wizard-triggers.jsx";
import { CONFLICT_MESSAGES, WIZARD_STEPS, newConfig, stepOfPath } from "../constants/index.js";
import {
  useCreatePipeline,
  usePipelineOptions,
  usePipelineVersion,
  usePublishConfig,
  useUpdatePipeline,
} from "../hooks/use-pipelines.js";
import { basicsSchema, checkConfig, issueMap, serverIssues } from "../schemas/index.js";
import { newIdempotencyKey, pipelinesService } from "../services/pipelines-service.js";
import { useWizardStore } from "../stores/wizard-store.js";

/** Vertical stepper that is a real list of buttons (Tab / Enter / Space), the current step marked with aria-current. */
function WizardStepper({ step, goTo, problems }) {
  const visited = useWizardStore((s) => s.visited);
  return (
    <nav aria-label="Pipeline steps" className="min-w-0">
      <ol className="flex gap-1 overflow-x-auto lg:flex-col">
        {WIZARD_STEPS.map((s, i) => (
          <li key={s.id}>
            <button
              type="button"
              onClick={() => goTo(s.id)}
              aria-current={step === s.id ? "step" : undefined}
              className={`flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-sm whitespace-nowrap outline-none focus-visible:ring-2 focus-visible:ring-ring ${
                step === s.id
                  ? "bg-accent font-medium text-foreground"
                  : "text-muted-foreground hover:bg-accent"
              }`}
            >
              <span className="flex size-5 shrink-0 items-center justify-center rounded-full border border-border-strong text-xs">
                {i + 1}
              </span>
              {s.label}
              {problems[s.id] && (visited[s.id] || step === "review") ? (
                <>
                  <CircleAlert aria-hidden="true" className="size-3.5 text-status-danger" />
                  <span className="sr-only">(needs attention)</span>
                </>
              ) : null}
            </button>
          </li>
        ))}
      </ol>
    </nav>
  );
}

function Banner({ children, tone = "danger", action }) {
  return (
    <div
      role="alert"
      className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-md border border-border-strong bg-secondary p-3 text-sm"
    >
      <p className={tone === "danger" ? "" : "text-muted-foreground"}>{children}</p>
      {action}
    </div>
  );
}

/** The wizard proper: runs once per loaded snapshot (the loader remounts it with a new `key` on reload). */
function WizardForm({ mode, workspaceId, snapshot, repository, repositories, options, onReload }) {
  const navigate = useNavigate();
  const can = useCan();
  const [params, setParams] = useSearchParams();
  const editing = mode === "edit";
  const setSaving = useWizardStore((s) => s.setSaving);
  const visit = useWizardStore((s) => s.visit);
  const requested = params.get("step");
  const step = WIZARD_STEPS.some((s) => s.id === requested) ? requested : "basics";
  const create = useCreatePipeline();
  const publish = usePublishConfig();
  const update = useUpdatePipeline();
  const limits = options.limits;
  const initialConfig = useMemo(
    () => snapshot.config ?? newConfig(limits),
    [snapshot.config, limits],
  );
  const baseline = useMemo(() => {
    const checked = checkConfig(initialConfig, limits);
    return checked.ok ? canonicalJson(checked.config) : canonicalJson(initialConfig);
  }, [initialConfig, limits]);

  const form = useForm({
    resolver: zodResolver(basicsSchema),
    defaultValues: {
      repositoryId: repository?.id ?? "",
      name: snapshot.name ?? "",
      description: snapshot.description ?? "",
      enabled: true,
      changeNote: "",
      config: initialConfig,
    },
  });
  const values = useWatch({ control: form.control });
  const config = values.config ?? initialConfig;
  const edit = (fn) => {
    const next = structuredClone(form.getValues("config"));
    fn(next);
    form.setValue("config", next, { shouldDirty: true });
  };
  const chosenRepository =
    repository ?? repositories.find((r) => r.id === values.repositoryId) ?? null;
  const repositoryLocked = Boolean(repository);

  const [serverProblems, setServerProblems] = useState([]);
  const [nameError, setNameError] = useState(null);
  const [banner, setBanner] = useState(null);
  const [testing, setTesting] = useState(false);
  const [leaving, setLeaving] = useState(false);
  const attempt = useRef({ signature: "", key: "" });
  const saved = useRef({ name: snapshot.name, description: snapshot.description ?? null });

  const checked = useMemo(() => checkConfig(config, limits), [config, limits]);
  const clientIssues = checked.ok ? [] : checked.issues;
  const enableIssue =
    !editing && values.enabled && !checkEnableable(config).ok
      ? [
          {
            path: "triggers",
            message:
              "To enable the pipeline, turn on at least one scan type and one trigger (or untick “Enable after creating”).",
          },
        ]
      : [];
  const issues = [
    ...clientIssues,
    ...enableIssue,
    ...serverProblems.filter((p) => p.path.startsWith("config")),
  ];
  const errors = issueMap(issues);
  const problems = { basics: Boolean(nameError), triggers: false, scans: false, controls: false };
  for (const issue of issues) problems[stepOfPath(issue.path)] = true;

  const dirty = form.formState.isDirty;
  useEffect(() => {
    const warn = (event) => {
      if (!form.formState.isDirty || useWizardStore.getState().saving) return;
      event.preventDefault();
    };
    window.addEventListener("beforeunload", warn);
    return () => window.removeEventListener("beforeunload", warn);
  }, [form.formState.isDirty]);
  useEffect(() => {
    visit(step);
  }, [step, visit]);
  useEffect(() => () => useWizardStore.getState().reset(), []);

  // the step lives in the URL; `repository` and `copy` must survive step changes
  const goTo = (id) =>
    setParams(
      (current) => {
        const merged = new URLSearchParams(current);
        if (id === "basics") merged.delete("step");
        else merged.set("step", id);
        return merged;
      },
      { replace: true, preventScrollReset: true },
    );
  const stepIndex = WIZARD_STEPS.findIndex((s) => s.id === step);
  const next = async () => {
    if (step === "basics") {
      const ok = await form.trigger(["repositoryId", "name", "description"]);
      if (!ok) return;
    }
    goTo(WIZARD_STEPS[stepIndex + 1].id);
  };
  const listPath = `/workspaces/${workspaceId}/pipelines`;
  const cancel = () => {
    if (dirty) setLeaving(true);
    else
      navigate(
        editing
          ? `${listPath}/${snapshot.id}`
          : repositoryLocked
            ? `/workspaces/${workspaceId}/repositories/${repository.id}`
            : listPath,
      );
  };

  const fail = (error) => {
    setBanner(null);
    const reason = error?.details?.reason;
    if (isApiError(error) && error.code === "VALIDATION_FAILED") {
      const list = serverIssues(error);
      setServerProblems(list);
      const first = list.find((p) => p.path.startsWith("config")) ?? list[0];
      if (list.some((p) => p.path === "name" || p.path === "description")) {
        setNameError(list.find((p) => p.path === "name")?.message ?? null);
        goTo("basics");
      } else if (first) goTo(stepOfPath(first.path));
      setBanner({
        text: "The server found problems in this pipeline. They are marked in the steps.",
      });
    } else if (reason === "name_taken") {
      setNameError(CONFLICT_MESSAGES.name_taken);
      goTo("basics");
    } else if (reason === "version_conflict") {
      setBanner({ conflict: true, text: CONFLICT_MESSAGES.version_conflict });
    } else if (reason && CONFLICT_MESSAGES[reason]) {
      setBanner({ text: CONFLICT_MESSAGES[reason] });
    } else if (reason === "fork_policy_requires_permission") {
      setBanner({
        text: "You need permission to allow fork pull requests to run. Set the fork policy back to “Do not run” or ask someone who can.",
      });
      goTo("triggers");
    } else if (isApiError(error) && error.code === "QUOTA_EXCEEDED") {
      const limit = options.pipelines?.limit;
      setBanner({
        text: limit
          ? `Your plan limit of ${limit} pipelines is reached.`
          : "Your plan limit of pipelines is reached.",
      });
    } else if (isApiError(error) && error.code === "ENTITLEMENT_REQUIRED") {
      setBanner({ text: "Your plan does not include pipelines." });
    } else {
      setBanner({
        text: describeError(error),
        reference: isApiError(error) ? error.correlationId : null,
      });
    }
  };

  const idempotencyKey = (payload) => {
    const signature = JSON.stringify(payload);
    if (attempt.current.signature !== signature)
      attempt.current = { signature, key: newIdempotencyKey() };
    return attempt.current.key;
  };

  const save = async () => {
    setBanner(null);
    setServerProblems([]);
    setNameError(null);
    const valid = await form.trigger(["repositoryId", "name", "description", "changeNote"]);
    if (!valid) return goTo("basics");
    if (!checked.ok || enableIssue.length) return goTo("review");
    const v = form.getValues();
    const name = v.name.trim();
    const description = v.description.trim();
    setSaving(true);
    try {
      if (!editing) {
        const body = {
          name,
          ...(description ? { description } : {}),
          enabled: v.enabled,
          config: checked.config,
        };
        const created = await create.mutateAsync({
          repositoryId: v.repositoryId,
          body,
          idempotencyKey: idempotencyKey({ repositoryId: v.repositoryId, body }),
        });
        form.reset(form.getValues());
        toast.success("Pipeline created");
        navigate(`${listPath}/${created.id}`);
        return;
      }
      const metaChanged =
        name !== saved.current.name || (description || null) !== saved.current.description;
      if (metaChanged) {
        await update.mutateAsync({
          pipelineId: snapshot.id,
          body: { name, description: description || null },
        });
        saved.current = { name, description: description || null };
      }
      if (canonicalJson(checked.config) === baseline) {
        form.reset(form.getValues());
        toast.success(metaChanged ? "Pipeline updated" : "No changes to save");
        navigate(`${listPath}/${snapshot.id}`);
        return;
      }
      const body = {
        expectedVersion: snapshot.version,
        config: checked.config,
        ...(v.changeNote.trim() ? { changeNote: v.changeNote.trim() } : {}),
      };
      const published = await publish.mutateAsync({
        pipelineId: snapshot.id,
        body,
        idempotencyKey: idempotencyKey({ id: snapshot.id, body }),
      });
      form.reset(form.getValues());
      toast.success(`Saved as version ${published.version}`);
      navigate(`${listPath}/${snapshot.id}`);
    } catch (error) {
      fail(error);
    } finally {
      setSaving(false);
    }
  };

  const pending = create.isPending || publish.isPending || update.isPending;
  const title = editing ? `Edit ${snapshot.name}` : "Create pipeline";
  return (
    <>
      <PageHeader
        title={title}
        description={
          editing
            ? "Saving publishes a new configuration version."
            : "A pipeline decides what is scanned and when."
        }
      />
      {banner ? (
        <Banner
          action={
            banner.conflict ? (
              <Button variant="secondary" onClick={onReload}>
                Reload the latest version
              </Button>
            ) : null
          }
        >
          {banner.text}
          {banner.reference ? (
            <span className="ml-2 text-xs text-subtle-foreground">
              Reference <span className="font-mono">{banner.reference}</span>
            </span>
          ) : null}
        </Banner>
      ) : null}
      <div className="grid grid-cols-[minmax(0,1fr)] gap-6 lg:grid-cols-[13rem_minmax(0,1fr)_16rem]">
        <WizardStepper step={step} goTo={goTo} problems={problems} />
        <div className="min-w-0">
          <h2 className="mb-4 text-base font-semibold">{WIZARD_STEPS[stepIndex].label}</h2>
          {step === "basics" ? (
            <BasicsStep
              form={form}
              repositories={repositories}
              repositoryLocked={repositoryLocked}
              repositoryName={chosenRepository?.fullName}
              editing={editing}
              nameError={nameError}
            />
          ) : null}
          {step === "triggers" ? (
            <TriggersStep
              config={config}
              edit={edit}
              errors={errors}
              options={options}
              defaultBranch={chosenRepository?.defaultBranch ?? null}
              canForkPolicy={can("pipeline.manage_fork_policy", { type: "workspace", workspaceId })}
            />
          ) : null}
          {step === "scans" ? (
            <ScansStep config={config} edit={edit} errors={errors} options={options} />
          ) : null}
          {step === "controls" ? (
            <ControlsStep config={config} edit={edit} errors={errors} options={options} />
          ) : null}
          {step === "review" ? (
            <ReviewStep
              form={form}
              config={checked.ok ? checked.config : config}
              issues={issues}
              goTo={goTo}
              editing={editing}
              currentVersion={snapshot.version}
              previousConfig={editing ? snapshot.config : null}
              onTest={() => setTesting(true)}
            />
          ) : null}
          <div className="mt-6 flex flex-wrap items-center justify-between gap-2 border-t border-border pt-4">
            <Button variant="ghost" onClick={cancel}>
              Cancel
            </Button>
            <div className="flex gap-2">
              {stepIndex > 0 ? (
                <Button variant="secondary" onClick={() => goTo(WIZARD_STEPS[stepIndex - 1].id)}>
                  Back
                </Button>
              ) : null}
              {step !== "review" ? (
                <Button onClick={next}>Next</Button>
              ) : (
                <Button onClick={save} disabled={pending || !checked.ok}>
                  {pending
                    ? "Saving…"
                    : editing
                      ? `Save as version ${snapshot.version + 1}`
                      : "Create pipeline"}
                </Button>
              )}
            </div>
          </div>
        </div>
        <WizardSummary
          name={values.name}
          repositoryName={chosenRepository?.fullName}
          config={config}
          editing={editing}
          nextVersion={snapshot.version + 1}
        />
      </div>
      <DryRunDialog
        draft={{
          repositoryId: values.repositoryId,
          defaultBranch: chosenRepository?.defaultBranch ?? null,
          name: values.name,
          config,
        }}
        open={testing}
        onOpenChange={setTesting}
      />
      <ConfirmDialog
        open={leaving}
        onOpenChange={setLeaving}
        title="Discard your changes?"
        description="You have unsaved changes. Leaving now throws them away."
        confirmLabel="Discard changes"
        destructive
        onConfirm={() => {
          form.reset(form.getValues());
          setLeaving(false);
          navigate(editing ? `${listPath}/${snapshot.id}` : listPath);
        }}
      />
    </>
  );
}

/**
 * The pipeline being edited or duplicated, read ONCE (no background refetch, no invalidation by mutations): a refetch that
 * changed the version under the user's hands would replace what they are typing. `reload` re-reads it explicitly.
 */
function useWizardSource(sourceId) {
  const tenantId = useTenantId();
  const pipeline = useQuery({
    queryKey: ["tenant", tenantId, "pipeline-wizard", sourceId],
    queryFn: ({ signal }) => pipelinesService.get(sourceId, { signal }),
    enabled: Boolean(sourceId),
    staleTime: Infinity,
    gcTime: 0,
    refetchOnWindowFocus: false,
    refetchOnReconnect: false,
  });
  const version = usePipelineVersion(sourceId, pipeline.data?.currentVersion?.version, {
    enabled: Boolean(pipeline.data?.currentVersion),
  });
  return { pipeline, version };
}

/**
 * Loads what the wizard needs (options, the pipeline and its current version when editing or duplicating, the repository)
 * and offers "Reload the latest version" for the optimistic-concurrency conflict. Needs `pipeline.manage` (enforced by the
 * route). @param {{ mode: "create" | "edit" }} props
 */
export function PipelineWizardPage({ mode }) {
  const { workspaceId, pipelineId } = useParams();
  const [params] = useSearchParams();
  const editing = mode === "edit";
  const repositoryParam = params.get("repository") ?? "";
  const sourceId = editing ? pipelineId : (params.get("copy") ?? "");

  const options = usePipelineOptions(workspaceId);
  const { pipeline: source, version } = useWizardSource(sourceId);
  const sourceData = source.data;
  const repositoryId = editing
    ? (sourceData?.repositoryId ?? "")
    : repositoryParam || sourceData?.repositoryId || "";
  const repositoryQuery = useRepository(repositoryId);
  const picker = useRepositoryList({
    workspaceId,
    status: "active",
    pageSize: 100,
    sort: "fullName:asc",
  });

  if (options.isPending || (sourceId && source.isPending))
    return <LoadingState label="Loading the wizard" />;
  if (options.isError) return <QueryErrorState error={options.error} onRetry={options.refetch} />;
  if (sourceId && source.isError)
    return <QueryErrorState error={source.error} onRetry={source.refetch} />;
  if (sourceData && (sourceData.workspaceId !== workspaceId || sourceData.deletedAt))
    return <NotFoundState />;
  if (sourceId && version.isError)
    return <QueryErrorState error={version.error} onRetry={version.refetch} />;
  if (sourceId && version.isPending) return <LoadingState label="Loading the current version" />;
  if (repositoryId && repositoryQuery.isPending)
    return <LoadingState label="Loading the repository" />;
  if (repositoryId && repositoryQuery.isError && !editing)
    return <QueryErrorState error={repositoryQuery.error} onRetry={repositoryQuery.refetch} />;
  const repository = repositoryQuery.data ?? null;
  if (repository && repository.workspaceId !== workspaceId) return <NotFoundState />;
  if (!editing && repository && (repository.status !== "active" || !repository.enabled))
    return (
      <>
        <PageHeader title="Create pipeline" />
        <p role="alert" className="rounded-md border border-border-strong bg-secondary p-3 text-sm">
          Pipelines can be created once the repository is active.{" "}
          <Link
            className="underline underline-offset-2"
            to={`/workspaces/${workspaceId}/repositories/${repository.id}`}
          >
            Back to the repository
          </Link>
        </p>
      </>
    );
  const snapshot = sourceId
    ? {
        id: sourceData.id,
        key: `${sourceData.id}:${version.data.version}`,
        name: editing ? sourceData.name : `${sourceData.name} copy`.slice(0, 100),
        description: sourceData.description,
        version: version.data.version,
        config: version.data.config,
      }
    : { id: null, key: "new", name: "", description: "", version: 0, config: null };
  const repositories = (picker.data?.items ?? []).filter((r) => r.status === "active" && r.enabled);
  const lockedRepository = repository
    ? { id: repository.id, fullName: repository.fullName, defaultBranch: repository.defaultBranch }
    : editing
      ? { id: sourceData.repositoryId, fullName: sourceData.repository.name, defaultBranch: null }
      : null;
  return (
    <WizardForm
      key={snapshot.key}
      mode={mode}
      workspaceId={workspaceId}
      snapshot={snapshot}
      repository={lockedRepository}
      repositories={repositories}
      options={options.data}
      onReload={() => source.refetch()}
    />
  );
}
