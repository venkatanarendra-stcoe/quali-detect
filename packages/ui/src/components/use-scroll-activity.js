import { useEffect } from "react";

/**
 * Marks a scroll container with `data-scrolling` while it scrolls and for `idleMs` afterwards, so `.qm-scroll`
 * (scroll.css) can fade its thin scrollbar in and out. No re-renders: it only toggles an attribute.
 * @param {import("react").RefObject<HTMLElement | null>} ref
 * @param {number} [idleMs]
 */
export function useScrollActivity(ref, idleMs = 900) {
  useEffect(() => {
    const el = ref.current;
    if (!el) return undefined;
    let timer;
    const onScroll = () => {
      el.setAttribute("data-scrolling", "");
      clearTimeout(timer);
      timer = setTimeout(() => el.removeAttribute("data-scrolling"), idleMs);
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      el.removeEventListener("scroll", onScroll);
      clearTimeout(timer);
    };
  }, [ref, idleMs]);
}
