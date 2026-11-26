import PDFDocument from "pdfkit";
import {
  REPORTING_LIMITS,
  REPORT_EXCLUSION_NOTICE,
  redactCredentialShapes,
} from "@qmentisai/shared";

/**
 * The PDF writer of the exports (docs/modules/reporting-dashboards/SPEC.md 7.3, 12 item 4, 13): pdfkit ONLY. No HTML is rendered, no
 * network is touched, no script, link, attachment or form is ever written; text is DRAWN with the PDF's built-in fonts (Helvetica,
 * Helvetica-Bold, Courier), so no font file is loaded from anywhere. The page template is fixed (A4, one header, one footer with the page
 * number and the exclusion notice). Long text is truncated with an ellipsis and every truncated cell is counted and printed. The charts are
 * vectors drawn here with the LIGHT-theme values of the design tokens (docs/design/DESIGN_SYSTEM.md 2.2 and 2.4: the severity text variants
 * are the light chart fills; the chart tokens are neutral); the accent is never used (a neutral dark is the primary series), and every
 * series also carries a hatch pattern and a direct label, so colour is never the only signal. The document has a non-personal title and no author.
 */

/** Thrown when the report would exceed the page cap (mapped to `too_large`). */
export class ReportTooLargeError extends Error {
  constructor(message = "The report exceeds the page limit.") {
    super(message);
    this.name = "ReportTooLargeError";
  }
}

/** Light-theme token values (DESIGN_SYSTEM 2.1, 2.2, 2.4). @type {Readonly<Record<string, string>>} */
export const PDF_COLORS = Object.freeze({
  foreground: "#151B1B",
  muted: "#586565",
  subtle: "#6B7777",
  border: "#DDE4E3",
  card: "#F5F7F7",
  white: "#FFFFFF",
  // severity: the light text/icon variants, which DESIGN_SYSTEM 2.2 says are the light-theme chart fills
  critical: "#B3202D",
  high: "#A8440A",
  medium: "#7A5800",
  low: "#1257B5",
  info: "#47535F",
  unknown: "#8A9AA3",
  // neutral chart series (DESIGN_SYSTEM 2.4, light values; the primary series is a neutral dark, never the accent)
  series1: "#3D4A50",
  series2: "#5E6F78",
  series3: "#8A9AA3",
  series4: "#C7D1D6",
});

/** Severity order, Critical to Info, and the hatch pattern of each (so colour is not the only signal). */
export const SEVERITY_ORDER = Object.freeze(["critical", "high", "medium", "low", "info"]);
export const SEVERITY_PATTERN = Object.freeze({
  critical: "solid",
  high: "diagonal",
  medium: "horizontal",
  low: "dots",
  info: "cross",
  unknown: "vertical",
});
export const SEVERITY_LABEL = Object.freeze({
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
  unknown: "Unknown",
});

const PAGE = Object.freeze({
  width: 595.28,
  height: 841.89,
  left: 40,
  right: 40,
  top: 54,
  bottom: 58,
});
const CONTENT_WIDTH = PAGE.width - PAGE.left - PAGE.right;

/**
 * Text that is safe to draw with the built-in fonts: credential shapes redacted, control characters removed, and anything outside the
 * Latin-1 plus common typographic range replaced with `?` (the built-in fonts have no glyph for it; the replacement keeps the length honest).
 * @param {unknown} value @returns {string}
 */
export function pdfText(value) {
  const text = redactCredentialShapes(String(value ?? ""));
  let out = "";
  for (const ch of text) {
    const cp = /** @type {number} */ (ch.codePointAt(0));
    if (cp >= 0x20 && cp <= 0x7e) out += ch;
    else if (cp >= 0xa0 && cp <= 0xff) out += ch;
    else if ("…–—‘’“”•".includes(ch)) out += ch;
    else if (cp === 0x09 || cp === 0x0a || cp === 0x0d || cp === 0x20) out += " ";
    else out += "?";
  }
  return out;
}

/** @param {string} hex */
const isDark = (hex) => {
  const n = Number.parseInt(hex.slice(1), 16);
  const lum = 0.2126 * ((n >> 16) & 255) + 0.7152 * ((n >> 8) & 255) + 0.0722 * (n & 255);
  return lum < 150;
};

/** @param {number} n */
export const formatInt = (n) => (Number.isFinite(n) ? Math.round(n).toLocaleString("en-US") : "-");
/** @param {number | null | undefined} n @param {number} [digits] */
export const formatDays = (n, digits = 1) =>
  n === null || n === undefined || !Number.isFinite(n) ? "n/a" : n.toFixed(digits);

/**
 * A report document. All drawing is synchronous; the caller loads its data first, then draws, then calls `finish()`.
 * @param {{ title: string, subtitle: string[], generatedAt: Date, maxPages?: number }} options `title` is a non-personal document title
 */
export function createPdfReport({
  title,
  subtitle,
  generatedAt,
  maxPages = REPORTING_LIMITS.pdfMaxPages,
}) {
  const doc = new PDFDocument({
    size: "A4",
    margins: { top: PAGE.top, bottom: PAGE.bottom, left: PAGE.left, right: PAGE.right },
    bufferPages: true,
    autoFirstPage: false,
    compress: true,
    info: {
      Title: pdfText(title),
      Subject: "QmentisAI report",
      Creator: "QmentisAI",
      Producer: "QmentisAI reporting worker",
      CreationDate: generatedAt,
    },
  });
  let pages = 0;
  const state = { truncatedCells: 0 };
  doc.on("pageAdded", () => {
    pages += 1;
    if (pages > maxPages) throw new ReportTooLargeError();
  });

  const bottomLimit = () => PAGE.height - PAGE.bottom;
  const ensure = (height) => {
    if (doc.y + height > bottomLimit()) doc.addPage();
  };

  const kit = {
    doc,
    state,
    get pageCount() {
      return pages;
    },
    width: CONTENT_WIDTH,

    /** First page and title block. */
    begin() {
      doc.addPage();
      doc
        .font("Helvetica-Bold")
        .fontSize(9)
        .fillColor(PDF_COLORS.muted)
        .text("QmentisAI", PAGE.left, PAGE.top - 22, { characterSpacing: 0.6 });
      doc.moveDown(0.2);
      doc
        .font("Helvetica-Bold")
        .fontSize(20)
        .fillColor(PDF_COLORS.foreground)
        .text(pdfText(title), PAGE.left, doc.y, { width: CONTENT_WIDTH });
      doc.moveDown(0.3);
      doc.font("Helvetica").fontSize(9.5).fillColor(PDF_COLORS.muted);
      for (const line of subtitle) doc.text(pdfText(line), { width: CONTENT_WIDTH });
      doc.moveDown(0.6);
      doc
        .moveTo(PAGE.left, doc.y)
        .lineTo(PAGE.width - PAGE.right, doc.y)
        .lineWidth(0.5)
        .strokeColor(PDF_COLORS.border)
        .stroke();
      doc.moveDown(0.8);
    },

    /** @param {string} text */
    heading(text) {
      ensure(60);
      doc.moveDown(0.6);
      doc
        .font("Helvetica-Bold")
        .fontSize(13)
        .fillColor(PDF_COLORS.foreground)
        .text(pdfText(text), PAGE.left, doc.y, { width: CONTENT_WIDTH });
      doc.moveDown(0.35);
    },

    /** @param {string} text @param {{ muted?: boolean, size?: number }} [o] */
    paragraph(text, { muted = false, size = 9.5 } = {}) {
      ensure(24);
      doc
        .font("Helvetica")
        .fontSize(size)
        .fillColor(muted ? PDF_COLORS.muted : PDF_COLORS.foreground)
        .text(pdfText(text), PAGE.left, doc.y, { width: CONTENT_WIDTH, lineGap: 2 });
      doc.moveDown(0.4);
    },

    /** A row of KPI tiles. @param {Array<{ label: string, value: string, note?: string }>} items */
    kpis(items) {
      const gap = 10;
      const w = (CONTENT_WIDTH - gap * (items.length - 1)) / items.length;
      const h = 62;
      ensure(h + 8);
      const y = doc.y;
      items.forEach((item, i) => {
        const x = PAGE.left + i * (w + gap);
        doc.roundedRect(x, y, w, h, 4).fillAndStroke(PDF_COLORS.card, PDF_COLORS.border);
        doc
          .font("Helvetica")
          .fontSize(8)
          .fillColor(PDF_COLORS.muted)
          .text(pdfText(item.label), x + 8, y + 8, {
            width: w - 16,
            lineBreak: false,
            ellipsis: true,
          });
        doc
          .font("Helvetica-Bold")
          .fontSize(20)
          .fillColor(PDF_COLORS.foreground)
          .text(pdfText(item.value), x + 8, y + 22, {
            width: w - 16,
            lineBreak: false,
            ellipsis: true,
          });
        if (item.note)
          doc
            .font("Helvetica")
            .fontSize(7.5)
            .fillColor(PDF_COLORS.subtle)
            .text(pdfText(item.note), x + 8, y + 48, {
              width: w - 16,
              lineBreak: false,
              ellipsis: true,
            });
      });
      doc.x = PAGE.left;
      doc.y = y + h + 12;
    },

    /**
     * A table. Cells are truncated to their column with an ellipsis (counted in `state.truncatedCells`); the header repeats on every page.
     * @param {{ columns: Array<{ key: string, header: string, width: number, align?: "left" | "right", mono?: boolean }>, rows: Array<Record<string, unknown>>, emptyText?: string }} options `width` is a weight
     */
    table({ columns, rows, emptyText = "No data for this selection." }) {
      const total = columns.reduce((s, c) => s + c.width, 0);
      const widths = columns.map((c) => (c.width / total) * CONTENT_WIDTH);
      const rowH = 15;
      const drawHeader = () => {
        ensure(rowH * 2);
        const y = doc.y;
        doc.rect(PAGE.left, y, CONTENT_WIDTH, rowH).fill(PDF_COLORS.card);
        let x = PAGE.left;
        columns.forEach((c, i) => {
          doc
            .font("Helvetica-Bold")
            .fontSize(8)
            .fillColor(PDF_COLORS.muted)
            .text(pdfText(c.header), x + 4, y + 4, {
              width: widths[i] - 8,
              align: c.align ?? "left",
              lineBreak: false,
              ellipsis: true,
            });
          x += widths[i];
        });
        doc.y = y + rowH;
      };
      drawHeader();
      if (rows.length === 0) {
        doc
          .font("Helvetica")
          .fontSize(8.5)
          .fillColor(PDF_COLORS.muted)
          .text(pdfText(emptyText), PAGE.left + 4, doc.y + 4, { width: CONTENT_WIDTH - 8 });
        doc.moveDown(1);
        return;
      }
      for (const row of rows) {
        if (doc.y + rowH > bottomLimit()) {
          doc.addPage();
          drawHeader();
        }
        const y = doc.y;
        let x = PAGE.left;
        columns.forEach((c, i) => {
          const font = c.mono ? "Courier" : "Helvetica";
          doc.font(font).fontSize(8.5);
          let text = pdfText(row[c.key] ?? "");
          const max = widths[i] - 8;
          if (doc.widthOfString(text) > max) {
            state.truncatedCells += 1;
            while (text.length > 0 && doc.widthOfString(`${text}…`) > max) text = text.slice(0, -1);
            text = `${text}…`;
          }
          doc
            .fillColor(PDF_COLORS.foreground)
            .text(text, x + 4, y + 4, { width: max, align: c.align ?? "left", lineBreak: false });
          x += widths[i];
        });
        doc
          .moveTo(PAGE.left, y + rowH)
          .lineTo(PAGE.width - PAGE.right, y + rowH)
          .lineWidth(0.4)
          .strokeColor(PDF_COLORS.border)
          .stroke();
        doc.y = y + rowH;
      }
      doc.x = PAGE.left;
      doc.moveDown(0.8);
    },

    /**
     * A horizontal bar chart: label, bar (colour plus pattern), value. Vector only.
     * @param {{ title?: string, bars: Array<{ label: string, value: number, color: string, pattern: string }>, unit?: string }} options
     */
    barChart({ title: chartTitle, bars, unit = "" }) {
      const barH = 14;
      const gap = 6;
      const labelW = 70;
      const valueW = 56;
      const h = bars.length * (barH + gap) + (chartTitle ? 18 : 4);
      ensure(h + 8);
      let y = doc.y;
      if (chartTitle) {
        doc
          .font("Helvetica-Bold")
          .fontSize(9)
          .fillColor(PDF_COLORS.foreground)
          .text(pdfText(chartTitle), PAGE.left, y);
        y += 18;
      }
      const max = Math.max(1, ...bars.map((b) => b.value));
      const areaW = CONTENT_WIDTH - labelW - valueW;
      for (const bar of bars) {
        doc
          .font("Helvetica")
          .fontSize(8.5)
          .fillColor(PDF_COLORS.foreground)
          .text(pdfText(bar.label), PAGE.left, y + 3, { width: labelW - 6, lineBreak: false });
        doc.rect(PAGE.left + labelW, y, areaW, barH).fill(PDF_COLORS.card);
        const w = bar.value > 0 ? Math.max(2, (bar.value / max) * areaW) : 0;
        if (w > 0) paintPattern(doc, PAGE.left + labelW, y, w, barH, bar.color, bar.pattern);
        doc
          .font("Helvetica-Bold")
          .fontSize(8.5)
          .fillColor(PDF_COLORS.foreground)
          .text(`${formatInt(bar.value)}${unit}`, PAGE.left + labelW + areaW + 6, y + 3, {
            width: valueW - 6,
            lineBreak: false,
          });
        y += barH + gap;
      }
      doc.x = PAGE.left;
      doc.y = y + 4;
    },

    /**
     * A horizontal stacked bar chart (one bar per category, segments per series) with a legend.
     * @param {{ title?: string, categories: Array<{ label: string, values: number[] }>, series: Array<{ label: string, color: string, pattern: string }> }} options
     */
    stackedBars({ title: chartTitle, categories, series }) {
      const barH = 14;
      const gap = 6;
      const labelW = 70;
      const valueW = 40;
      const h = categories.length * (barH + gap) + (chartTitle ? 18 : 4) + 18;
      ensure(h + 8);
      let y = doc.y;
      if (chartTitle) {
        doc
          .font("Helvetica-Bold")
          .fontSize(9)
          .fillColor(PDF_COLORS.foreground)
          .text(pdfText(chartTitle), PAGE.left, y);
        y += 18;
      }
      const areaW = CONTENT_WIDTH - labelW - valueW;
      const max = Math.max(1, ...categories.map((c) => c.values.reduce((s, v) => s + v, 0)));
      for (const category of categories) {
        doc
          .font("Helvetica")
          .fontSize(8.5)
          .fillColor(PDF_COLORS.foreground)
          .text(pdfText(category.label), PAGE.left, y + 3, { width: labelW - 6, lineBreak: false });
        doc.rect(PAGE.left + labelW, y, areaW, barH).fill(PDF_COLORS.card);
        let x = PAGE.left + labelW;
        category.values.forEach((value, i) => {
          const w = (value / max) * areaW;
          if (w > 0.4) paintPattern(doc, x, y, w, barH, series[i].color, series[i].pattern);
          x += w;
        });
        const total = category.values.reduce((s, v) => s + v, 0);
        doc
          .font("Helvetica-Bold")
          .fontSize(8.5)
          .fillColor(PDF_COLORS.foreground)
          .text(formatInt(total), PAGE.left + labelW + areaW + 6, y + 3, {
            width: valueW - 6,
            lineBreak: false,
          });
        y += barH + gap;
      }
      legend(doc, series, PAGE.left + labelW, y + 2);
      doc.x = PAGE.left;
      doc.y = y + 20;
    },

    /**
     * A stacked area chart over days (bottom series first) with gridlines, axis labels, a legend and a direct label of the last value of
     * every series. Vector only.
     * @param {{ title?: string, days: string[], series: Array<{ label: string, color: string, pattern: string, values: number[] }> }} options
     */
    stackedArea({ title: chartTitle, days, series }) {
      const h = 170;
      ensure(h + 56);
      let top = doc.y;
      if (chartTitle) {
        doc
          .font("Helvetica-Bold")
          .fontSize(9)
          .fillColor(PDF_COLORS.foreground)
          .text(pdfText(chartTitle), PAGE.left, top);
        top += 16;
      }
      const left = PAGE.left + 34;
      const right = PAGE.width - PAGE.right - 90;
      const bottom = top + h - 24;
      const plotH = bottom - top - 6;
      const n = days.length;
      const totals = days.map((_, i) => series.reduce((s, x) => s + (x.values[i] ?? 0), 0));
      const max = niceMax(Math.max(1, ...totals));
      const xAt = (i) => (n <= 1 ? left : left + (i / (n - 1)) * (right - left));
      const yAt = (v) => bottom - (v / max) * plotH;
      // gridlines and y axis labels
      for (let g = 0; g <= 4; g += 1) {
        const v = (max / 4) * g;
        doc
          .moveTo(left, yAt(v))
          .lineTo(right, yAt(v))
          .lineWidth(0.4)
          .strokeColor(PDF_COLORS.border)
          .stroke();
        doc
          .font("Helvetica")
          .fontSize(7.5)
          .fillColor(PDF_COLORS.subtle)
          .text(formatInt(v), PAGE.left, yAt(v) - 3, {
            width: 30,
            align: "right",
            lineBreak: false,
          });
      }
      // stack, top series last so the bottom series is drawn first
      const lower = days.map(() => 0);
      series.forEach((s) => {
        const upper = lower.map((l, i) => l + (s.values[i] ?? 0));
        doc.save();
        doc.moveTo(xAt(0), yAt(lower[0]));
        for (let i = 0; i < n; i += 1) doc.lineTo(xAt(i), yAt(upper[i]));
        for (let i = n - 1; i >= 0; i -= 1) doc.lineTo(xAt(i), yAt(lower[i]));
        doc.closePath();
        doc.clip();
        paintPattern(doc, left, top, right - left, bottom - top, s.color, s.pattern);
        doc.restore();
        doc.moveTo(xAt(0), yAt(upper[0]));
        for (let i = 1; i < n; i += 1) doc.lineTo(xAt(i), yAt(upper[i]));
        doc.lineWidth(0.8).strokeColor(s.color).stroke();
        lower.forEach((_, i) => {
          lower[i] = upper[i];
        });
      });
      // direct labels at the right edge (the last value of each series) and x axis labels
      let acc = 0;
      series.forEach((s) => {
        const v = s.values[n - 1] ?? 0;
        const mid = acc + v / 2;
        acc += v;
        doc
          .font("Helvetica")
          .fontSize(7.5)
          .fillColor(PDF_COLORS.foreground)
          .text(`${pdfText(s.label)} ${formatInt(v)}`, right + 6, yAt(mid) - 4, {
            width: 84,
            lineBreak: false,
            ellipsis: true,
          });
      });
      const ticks = n <= 1 ? [0] : [0, Math.floor((n - 1) / 2), n - 1];
      for (const i of ticks)
        doc
          .font("Helvetica")
          .fontSize(7.5)
          .fillColor(PDF_COLORS.subtle)
          .text(days[i], xAt(i) - 25, bottom + 4, { width: 50, align: "center", lineBreak: false });
      legend(doc, series, left, bottom + 18);
      doc.x = PAGE.left;
      doc.y = bottom + 38;
    },

    /** Finishes every page with the footer and ends the document. @param {string} templateTitle */
    finish(templateTitle) {
      const range = doc.bufferedPageRange();
      for (let i = 0; i < range.count; i += 1) {
        doc.switchToPage(range.start + i);
        const y = PAGE.height - PAGE.bottom + 14;
        doc.page.margins.bottom = 0; // allow drawing in the footer band without opening a new page
        doc
          .moveTo(PAGE.left, y - 6)
          .lineTo(PAGE.width - PAGE.right, y - 6)
          .lineWidth(0.4)
          .strokeColor(PDF_COLORS.border)
          .stroke();
        doc.font("Helvetica").fontSize(7.5).fillColor(PDF_COLORS.subtle);
        doc.text(
          pdfText(`QmentisAI  |  ${templateTitle}  |  ${REPORT_EXCLUSION_NOTICE}`),
          PAGE.left,
          y,
          { width: CONTENT_WIDTH - 70, lineBreak: false, ellipsis: true },
        );
        doc.text(`Page ${i + 1} of ${range.count}`, PAGE.width - PAGE.right - 70, y, {
          width: 70,
          align: "right",
          lineBreak: false,
        });
      }
      doc.end();
    },
  };
  return kit;
}

/** Axis maximum rounded up to 1, 2, 5 times a power of ten. @param {number} v */
function niceMax(v) {
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 4, 5, 10]) if (v <= m * p) return m * p;
  return 10 * p;
}

/** @param {any} doc @param {Array<{ label: string, color: string, pattern: string }>} series @param {number} x @param {number} y */
function legend(doc, series, x, y) {
  let cx = x;
  for (const s of series) {
    paintPattern(doc, cx, y, 12, 8, s.color, s.pattern);
    doc
      .font("Helvetica")
      .fontSize(7.5)
      .fillColor(PDF_COLORS.foreground)
      .text(pdfText(s.label), cx + 16, y, { lineBreak: false });
    cx += 22 + doc.widthOfString(pdfText(s.label)) + 10;
  }
}

/**
 * Fills a rectangle with a colour and a hatch (so a series differs by more than colour). Clipped to the rectangle.
 * @param {any} doc @param {number} x @param {number} y @param {number} w @param {number} h @param {string} color
 * @param {string} pattern `solid`, `diagonal`, `horizontal`, `vertical`, `cross` or `dots`
 */
function paintPattern(doc, x, y, w, h, color, pattern) {
  doc.save();
  doc.rect(x, y, w, h).clip();
  doc.rect(x, y, w, h).fill(color);
  const line = isDark(color) ? "#FFFFFF" : PDF_COLORS.series1;
  doc.lineWidth(0.7).strokeColor(line).opacity(0.85);
  const step = 5;
  if (pattern === "diagonal" || pattern === "cross") {
    for (let d = -h; d < w + h; d += step) doc.moveTo(x + d, y + h).lineTo(x + d + h, y);
    doc.stroke();
  }
  if (pattern === "cross") {
    for (let d = -h; d < w + h; d += step) doc.moveTo(x + d, y).lineTo(x + d + h, y + h);
    doc.stroke();
  }
  if (pattern === "horizontal") {
    for (let yy = y + 2.5; yy < y + h; yy += step) doc.moveTo(x, yy).lineTo(x + w, yy);
    doc.stroke();
  }
  if (pattern === "vertical") {
    for (let xx = x + 2.5; xx < x + w; xx += step) doc.moveTo(xx, y).lineTo(xx, y + h);
    doc.stroke();
  }
  if (pattern === "dots") {
    for (let xx = x + 3; xx < x + w; xx += step + 1)
      for (let yy = y + 3; yy < y + h; yy += step + 1) doc.circle(xx, yy, 0.9).fill(line);
  }
  doc.opacity(1);
  doc.restore();
}
