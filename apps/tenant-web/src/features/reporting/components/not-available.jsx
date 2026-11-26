/**
 * A value the API could not give: a dash with the reason in the tooltip and in text for assistive technology. A null is NOT AVAILABLE,
 * never 0 (the reporting DTOs use null for "not recorded" or "not part of this snapshot").
 * @param {{ reason?: string }} props
 */
export function NotAvailable({
  reason = "Not available: this value was not recorded for this day.",
}) {
  return (
    <span title={reason} className="text-muted-foreground">
      <span aria-hidden="true">—</span>
      <span className="sr-only">Not available. {reason}</span>
    </span>
  );
}

/** A count that may be null. @param {{ value: number | null | undefined, reason?: string }} props */
export function MaybeCount({ value, reason }) {
  return value === null || value === undefined ? <NotAvailable reason={reason} /> : value;
}
