import { useRef } from "react";
import { useScrollActivity } from "./use-scroll-activity.js";

const join = (...parts) => parts.filter(Boolean).join(" ");

/**
 * Page frame for the Tenant Application: the page itself never scrolls. It fills the viewport below the app chrome
 * (`offset`, default 3rem = the 1.5rem `main` padding top and bottom; the app shell may add `--app-shell-extra` (the mobile menu strip), the same as `WizardLayout`; at least 24rem tall). The
 * header (breadcrumb slot, title, description, actions slot) stays put; ONLY the content region scrolls, with the thin
 * fading scrollbar of `scroll.css`. Make it a flex column that its child fills with `scroll={false}`, e.g. to host a
 * `DataTable height="fill"` or a `WizardLayout fill` that scroll internally.
 * @param {{ title: import("react").ReactNode, description?: import("react").ReactNode,
 *   breadcrumb?: import("react").ReactNode, actions?: import("react").ReactNode, offset?: string, scroll?: boolean,
 *   className?: string, contentClassName?: string, children: import("react").ReactNode }} props
 *   `breadcrumb` is any node (typically a `<nav aria-label="Breadcrumb">`). Keep at most one mint primary action in
 *   `actions`. With `scroll` (default) the content region scrolls; with `scroll={false}` it is `overflow-hidden`.
 */
export function AppPageLayout({
  title,
  description,
  breadcrumb,
  actions,
  offset = "3rem",
  scroll = true,
  className,
  contentClassName,
  children,
}) {
  const contentRef = useRef(null);
  useScrollActivity(contentRef);
  return (
    <div
      data-app-page=""
      className={join(
        "flex h-[calc(100dvh-var(--app-page-offset)-var(--app-shell-extra,0rem))] min-h-[24rem] flex-col",
        className,
      )}
      style={{ "--app-page-offset": offset }}
    >
      <header data-app-page-header="" className="z-10 mb-4 shrink-0 bg-background">
        {breadcrumb ? <div className="mb-1 min-w-0 text-sm">{breadcrumb}</div> : null}
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h1 className="text-xl leading-7 font-semibold">{title}</h1>
            {description ? (
              <p className="mt-1 text-sm text-muted-foreground">{description}</p>
            ) : null}
          </div>
          {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
        </div>
      </header>
      <div
        ref={contentRef}
        data-app-page-content=""
        className={join(
          "qm-scroll min-h-0 min-w-0 flex-1",
          scroll ? "overflow-y-auto pr-1 pb-4" : "flex flex-col overflow-hidden",
          contentClassName,
        )}
      >
        {children}
      </div>
    </div>
  );
}
