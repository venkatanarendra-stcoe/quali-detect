import { useEffect, useId, useRef, useState } from "react";

const join = (...parts) => parts.filter(Boolean).join(" ");

/* Inline icons (lucide paths): packages/ui has no icon dependency and none is added for three glyphs. */
function Icon({ className, children }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      {children}
    </svg>
  );
}
const CheckIcon = ({ className }) => (
  <Icon className={className}>
    <path d="M20 6 9 17l-5-5" />
  </Icon>
);
const AlertIcon = ({ className }) => (
  <Icon className={className}>
    <circle cx="12" cy="12" r="10" />
    <line x1="12" x2="12" y1="8" y2="12" />
    <line x1="12" x2="12.01" y1="16" y2="16" />
  </Icon>
);
const ChevronIcon = ({ className }) => (
  <Icon className={className}>
    <path d="m6 9 6 6 6-6" />
  </Icon>
);

const normalize = (steps) => steps.map((s) => (typeof s === "string" ? { id: s, label: s } : s));

/**
 * Wizard stepper. One list, two looks: a horizontal underline indicator, and (from 1024 px, `orientation="responsive"`)
 * a vertical list. Completed and error steps carry an icon AND text, never colour alone; the current step has
 * `aria-current="step"`. Steps are buttons only when `onStepChange` is given.
 * @param {{ steps: Array<string | { id: string, label: string }>, current: string | number,
 *   stepStatus?: Record<string, "complete" | "error">, stepDisabled?: Record<string, boolean>,
 *   onStepChange?: (id: string) => void, label?: string, orientation?: "responsive" | "horizontal", className?: string }} props
 */
export function Stepper({
  steps,
  current,
  stepStatus = {},
  stepDisabled = {},
  onStepChange,
  label = "Progress",
  orientation = "responsive",
  className,
}) {
  const list = normalize(steps);
  const currentId = typeof current === "number" ? list[current]?.id : current;
  const vertical = orientation === "responsive";
  const listRef = useRef(null);
  useEffect(() => {
    // the horizontal indicator scrolls sideways on narrow screens: keep the current step in view
    listRef.current
      ?.querySelector('[aria-current="step"]')
      ?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [currentId]);
  return (
    <nav aria-label={label} className={join("min-w-0", className)}>
      <ol
        ref={listRef}
        className={join(
          "flex gap-x-4 gap-y-1 overflow-x-auto p-0.5",
          vertical ? "lg:flex-col lg:gap-x-0 lg:overflow-visible" : "border-b border-border",
          !vertical && "gap-x-6",
        )}
      >
        {list.map((step, index) => {
          const active = step.id === currentId;
          const status =
            stepStatus[step.id] ??
            (typeof current === "number" && index < current ? "complete" : undefined);
          const body = (
            <>
              <span
                className={join(
                  "flex size-5 shrink-0 items-center justify-center rounded-full border text-xs",
                  status === "error"
                    ? "border-status-danger text-status-danger"
                    : status === "complete"
                      ? "border-status-success text-status-success"
                      : "border-border-strong",
                )}
              >
                {status === "error" ? (
                  <AlertIcon className="size-3.5" />
                ) : status === "complete" ? (
                  <CheckIcon className="size-3" />
                ) : (
                  index + 1
                )}
              </span>
              {step.label}
              {status === "error" ? <span className="sr-only"> (needs attention)</span> : null}
              {status === "complete" ? <span className="sr-only"> (completed)</span> : null}
            </>
          );
          const look = join(
            "flex items-center gap-2 text-sm whitespace-nowrap",
            vertical
              ? "-mb-px border-b-2 pb-2 lg:mb-0 lg:w-full lg:rounded-sm lg:border-b-0 lg:px-2 lg:py-1.5"
              : "-mb-px border-b-2 pb-2",
            active
              ? vertical
                ? "border-foreground font-medium text-foreground lg:bg-accent"
                : "border-foreground font-medium text-foreground"
              : "border-transparent text-muted-foreground",
          );
          return (
            <li key={step.id} aria-current={!onStepChange && active ? "step" : undefined}>
              {onStepChange ? (
                <button
                  type="button"
                  aria-current={active ? "step" : undefined}
                  disabled={Boolean(stepDisabled[step.id])}
                  onClick={() => onStepChange(step.id)}
                  className={join(
                    look,
                    "text-left outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-60",
                    !active && !stepDisabled[step.id] && "hover:text-foreground lg:hover:bg-accent",
                  )}
                >
                  {body}
                </button>
              ) : (
                <div className={look}>{body}</div>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/**
 * Wizard page frame shared by both apps (no router, no app imports). It fills the viewport minus `offset` (the app chrome
 * above the page; at least 32rem tall): header on top, stepper and summary stay put, ONLY the form column scrolls, and
 * the action bar sits under it, so the page itself never scrolls. From 1280 px: stepper left, summary right. Below
 * 1280 px the summary is a disclosure above the form; below 1024 px the stepper is a horizontal indicator.
 * @param {{ title: string, description?: string, banner?: import("react").ReactNode,
 *   steps: Array<string | { id: string, label: string }>, current: string | number,
 *   onStepChange?: (id: string) => void, stepStatus?: Record<string, "complete" | "error">,
 *   stepDisabled?: Record<string, boolean>, stepperLabel?: string, summary?: import("react").ReactNode,
 *   summaryTitle?: string, actions: import("react").ReactNode, offset?: string,
 *   children: import("react").ReactNode }} props
 *   `actions` is the content of the bar: put the cancel control first and the Back/Next/Create group last.
 *   `offset` is a CSS length (default 6rem = 3rem top bar + 3rem page padding).
 */
export function WizardLayout({
  title,
  description,
  banner,
  steps,
  current,
  onStepChange,
  stepStatus,
  stepDisabled,
  stepperLabel = "Steps",
  summary,
  summaryTitle = "Summary",
  actions,
  offset = "6rem",
  children,
}) {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  return (
    <div
      data-wizard-layout=""
      className="flex h-[calc(100dvh-var(--wizard-offset))] min-h-[32rem] flex-col"
      style={{ "--wizard-offset": offset }}
    >
      <header data-wizard="header" className="mb-4 shrink-0">
        <h1 className="text-xl leading-7 font-semibold">{title}</h1>
        {description ? <p className="mt-1 text-sm text-muted-foreground">{description}</p> : null}
      </header>
      {banner ? <div className="shrink-0">{banner}</div> : null}
      {summary ? (
        <div className="mb-4 shrink-0 rounded-md border border-border bg-card xl:hidden">
          <button
            type="button"
            aria-expanded={open}
            aria-controls={panelId}
            onClick={() => setOpen((v) => !v)}
            className="flex w-full items-center justify-between gap-2 rounded-md px-3 py-2 text-sm font-medium outline-none focus-visible:ring-2 focus-visible:ring-ring"
          >
            {summaryTitle}
            <ChevronIcon className={join("size-4 transition-transform", open && "rotate-180")} />
          </button>
          <div
            id={panelId}
            hidden={!open}
            className="max-h-[40dvh] overflow-y-auto border-t border-border p-3"
          >
            {summary}
          </div>
        </div>
      ) : null}
      <div className="grid min-h-0 flex-1 grid-cols-[minmax(0,1fr)] grid-rows-[auto_minmax(0,1fr)] gap-x-6 gap-y-3 lg:grid-cols-[13rem_minmax(0,1fr)] lg:grid-rows-[minmax(0,1fr)] xl:grid-cols-[13rem_minmax(0,1fr)_16rem]">
        <div data-wizard="stepper" className="min-h-0 min-w-0 p-0.5 lg:overflow-y-auto">
          <Stepper
            steps={steps}
            current={current}
            stepStatus={stepStatus}
            stepDisabled={stepDisabled}
            onStepChange={onStepChange}
            label={stepperLabel}
          />
        </div>
        <div data-wizard="column" className="flex min-h-0 min-w-0 flex-col">
          <div
            data-wizard="form"
            className={join(
              "min-h-0 min-w-0 flex-1 overflow-y-auto pr-2 pb-4 [scroll-padding-bottom:1.5rem]",
              "[&_:is(input,select,textarea,button,a[href],[tabindex])]:scroll-mb-6",
            )}
          >
            {children}
          </div>
          <div data-wizard="actions" className="shrink-0 border-t border-border bg-background py-3">
            <div className="flex flex-wrap items-center justify-between gap-2">{actions}</div>
          </div>
        </div>
        {summary ? (
          <aside
            data-wizard="summary"
            aria-label={summaryTitle}
            className="hidden max-h-full min-h-0 self-start overflow-y-auto xl:block"
          >
            {summary}
          </aside>
        ) : null}
      </div>
    </div>
  );
}
