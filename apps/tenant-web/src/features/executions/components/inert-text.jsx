import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { inertText } from "../constants/decision-text.js";

/**
 * Untrusted text (model-written summary and reasons) shown as plain text only: it is cleaned by `inertText`, rendered as a
 * React text child (so escaped; no Markdown, no HTML, no links), clamped to three lines with a "Show more" button that
 * announces its state, and wrapped anywhere so a very long word cannot widen the page.
 * @param {{ children: unknown, max?: number, className?: string }} props
 */
export function ClampedText({ children, max = 1000, className = "" }) {
  const text = inertText(children, max);
  const ref = useRef(null);
  const id = useId();
  const [expanded, setExpanded] = useState(false);
  const [overflows, setOverflows] = useState(false);
  useLayoutEffect(() => {
    const el = ref.current;
    if (el && !expanded) setOverflows(el.scrollHeight > el.clientHeight + 1);
  }, [text, expanded]);
  useEffect(() => {
    const onResize = () => {
      const el = ref.current;
      if (el && !expanded) setOverflows(el.scrollHeight > el.clientHeight + 1);
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [expanded]);
  if (!text) return null;
  return (
    <span className={`block min-w-0 ${className}`}>
      <span
        id={id}
        ref={ref}
        className={`block [overflow-wrap:anywhere] ${expanded ? "" : "line-clamp-3"}`}
      >
        {text}
      </span>
      {overflows || expanded ? (
        <button
          type="button"
          aria-expanded={expanded}
          aria-controls={id}
          onClick={() => setExpanded((v) => !v)}
          className="mt-0.5 rounded-sm text-xs underline underline-offset-2 outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {expanded ? "Show less" : "Show more"}
        </button>
      ) : null}
    </span>
  );
}

/** A short untrusted string (provider, model, a path) in mono, cleaned and wrapped anywhere. Identifiers only. */
export function InertMono({ children, max = 300, className = "" }) {
  const text = inertText(children, max);
  if (!text) return null;
  return <span className={`font-mono text-xs [overflow-wrap:anywhere] ${className}`}>{text}</span>;
}
