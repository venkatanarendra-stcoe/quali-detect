import { useRef } from "react";

/**
 * Focus return for a Radix dialog or sheet that is opened by state rather than by its own trigger: Radix prevents its default
 * and focuses `triggerRef`, which does not exist here, so focus would be lost to the page body. This remembers the element that
 * had focus when the content opened and gives it focus again on close (keyboard users keep their place).
 * Spread the two handlers on `DialogContent` / `SheetContent`.
 */
export function useReturnFocus() {
  const opener = useRef(/** @type {Element | null} */ (null));
  return {
    onOpenAutoFocus: () => {
      opener.current = document.activeElement;
    },
    onCloseAutoFocus: (event) => {
      event.preventDefault();
      if (opener.current instanceof HTMLElement && opener.current.isConnected)
        opener.current.focus();
    },
  };
}
