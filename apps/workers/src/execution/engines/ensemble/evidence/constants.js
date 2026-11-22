/**
 * Evidence caps (docs/modules/scan-engines/SPEC.md 5.13.2, accepted by the owner 2026-11-19, OQ-11; part J). One place; every figure is asserted
 * by ENG-S13.
 */
export const EVIDENCE_CAPS = Object.freeze({
  /** An enclosing block longer than this is replaced by the window. */
  blockLines: 80,
  /** Lines before and after the finding in the fallback window (21 lines in all). */
  windowRadius: 10,
  /** One stored line; a longer line is cut and ends with {@link CUT_MARKER}. */
  lineChars: 300,
  /** The whole snippet after redaction. */
  snippetBytes: 4096,
  /** All evidence fields of one finding (the shared schema also refuses more). */
  evidenceBytes: 8192,
  /** Findings that get a snippet per task, highest severity first, ties by path and line. */
  snippetsPerTask: 500,
  /** Locations sent to the extractor per task. */
  extractorLocations: 2000,
  /** A file over this size is not parsed (the window only). */
  parseFileBytes: 1024 * 1024,
  /** A file over this size gets no evidence at all (a window or a masked line needs the whole file in memory). */
  windowFileBytes: 4 * 1024 * 1024,
  /** Secrets: lines shown before and after the masked line (each of them masked as well). */
  secretContextLines: 2,
});

/** Ends a line that was cut at the line cap. */
export const CUT_MARKER = " [cut]";
/** Replaces a context line that could not be masked with confidence. */
export const WITHHELD_LINE = "[line withheld]";
