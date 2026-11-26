# Reporting and Dashboards, Part E: mutation sweep backlog

Written 2026-11-26 for Part E (`SPEC.md` 16.2, `AS_BUILT_E.md`). It follows the model of `docs/modules/findings/MUTATION_BACKLOG.md`. Survivors are NOT triaged (the owner asked only that the security-critical ones be starred and killed). A star marks a survivor whose line is a tenant scope, permission gate, redaction, CSV or PDF safety, object key validation, input validation or limit at first sight.

**Status:** sample of **380 mutants** over the reporting code: **224 killed, 155 survived, 0 timeouts, 1 invalid** (kill rate 59.1 percent of the 379 valid mutants; 60.1 percent in the memory pass, 50.0 percent in the database pass). 43 survivors are starred; Part E added `RPT-SM01` to `RPT-SM06` (and the E checks `RPT-S13` to `RPT-S14`, `RPT-S10f`, `RPT-S08h`), re-ran the starred lines and killed 34 of the 43 (the residue is listed in section 4 with the reason it is judged equivalent or low value).

## 1. Method and tooling

The tooling of the scan engines and Findings sweeps was reused (`apps/api/scripts/mutation-sweep.js`, `mutation-worker.js`, `mutation-hook.js`, `mutation-register.js`). One additive change was made: `MUTATION_GROUP=reporting` makes the worker run the checks of `helpers/reporting/index.js` (the same mechanism as `MUTATION_GROUP=findings`), skipping the ones that need the database (a Proxy world throws `NEEDS_DB`). Targets: `MUTATION_TARGETS=packages/shared/src/reporting,apps/workers/src/reporting,apps/api/src/modules/reporting,packages/db/src/reporting` (64 files, 1,915 candidate mutants).

- **Memory pass** (database-free, about 90 seconds with 4 jobs): `map` found 65 checks that run without a database (2 of them, `RPT-S02` and `RPT-S08f`, are not green alone and are excluded), then `run --per-file 20 --seed 20261126 --jobs 4`: **342 mutants, 205 killed, 136 survived (85 of them on lines no database-free check executes), 0 timeouts, 1 invalid.**
- **Database pass** (in place, the real suite filtered with `SECURITY_SUITE_ONLY`, one ephemeral cluster per mutant, about 15 to 25 seconds each): `dbsweep --count 2 --seed 20261127` over 19 files of `apps/api/src/modules/reporting`, `packages/db/src/reporting/{read,exports,rollup}` and `apps/workers/src/reporting/rollup`, filtered to the checks of the part that owns the file (`RPT-S01|S02|S07|S08|S11`, `RPT-S01|S03|S04|S05|S06|RPTAM`, `RPT-S09|S10|S08h`): **38 mutants, 19 killed, 19 survived.** The tree was restored after each mutant; `git status` after the sweep showed no change.
- Seeds 20261126 and 20261127. Operators as in the Findings sweep.

## 2. Limits of this sweep (read before trusting a kill rate)

- A sample: at most 20 mutants per file in the memory pass and 2 per file in the database pass. **Not swept:** the controllers and routes beyond the 2 mutants per file the memory pass drew, the SQL text of the views and migrations (a statement is not an operator target), `apps/workers/src/reporting/export/templates.js` beyond 5 mutants, the Part D UI (outside the suite by ADR-008 area 20).
- The database pass was run against the checks of the owning part, not the whole suite (about 12 minutes). A survivor there is a candidate, not proof.
- 85 memory-pass survivors are on lines no database-free check executes: they are covered (or not) by the database checks and are only meaningful after the database pass; the database pass sampled 38 of them.
- Mutation in memory does not change a source FILE that a check reads. Equivalent mutants are not removed (a log argument, a message text, a sort tie-break, a cap by one on a value no check pins).
- The `RPT-S13`/`RPT-S14` checks need the second API process and are therefore database-class: they are not part of the memory pass.

## 3. Survivors (not triaged; a star marks a security-relevant line)

### 3.1 Memory pass



### apps/api/src/modules/reporting/controllers/export.js

killed 2, survived 2, timeout 0, invalid 0

- `M0217` line 29 int (not executed by any Docker-free check): `202` -> `203` in `reply.code(202).success(await service.create(actorFrom(request), request.body)),`
- `M0218` line 80 drop-call (not executed by any Docker-free check): `await service.remove(actorFrom(request), request.authz.resource.id);` -> `;` in `await service.remove(actorFrom(request), request.authz.resource.id);`

### apps/api/src/modules/reporting/controllers/read.js

killed 0, survived 2, timeout 0, invalid 0

- `M0219` line 12 logic (not executed by any Docker-free check): `&&` -> `||` in `if (v && typeof v === "object")`
- `M0220` line 38 drop-call (not executed by any Docker-free check): `reply.set("ETag", etag);` -> `;` in `reply.set("ETag", etag);`

### apps/api/src/modules/reporting/export-authorization.js

killed 12, survived 5, timeout 0, invalid 0

- ★ `M0223` line 21 drop-call: `next();` -> `;` in `next();`
- `M0236` line 31 eq (not executed by any Docker-free check): `!==` -> `===` in `if (typeof id !== "string") return null;`
- `M0237` line 34 bool (not executed by any Docker-free check): `true` -> `false` in `select: { id: true },`
- ★ `M0225` line 76 return-undefined: `return next();` -> `return undefined;` in `return next();`
- ★ `M0230` line 117 return-undefined: `return next();` -> `return undefined;` in `return next();`

### apps/api/src/modules/reporting/export-object-reader.js

killed 13, survived 1, timeout 0, invalid 0

- ★ `M0239` line 24 logic: `||` -> `&&` in `typeof tenantId !== "string" ||`

### apps/api/src/modules/reporting/mappers/export.js

killed 0, survived 2, timeout 0, invalid 0

- `M0252` line 15 logic (not executed by any Docker-free check): `&&` -> `||` in `period: row.periodFrom && row.periodTo ? { from: row.periodFrom, to: row.periodTo } : null,`
- `M0253` line 19 int (not executed by any Docker-free check): `200` -> `201` in `displayName: (names.get(row.requestedByUserId) ?? "Former member").slice(0, 200),`

### apps/api/src/modules/reporting/mappers/read.js

killed 1, survived 2, timeout 0, invalid 0

- `M0255` line 231 int (not executed by any Docker-free check): `1` -> `2` in `let open = tail.at(-1).open;`
- `M0256` line 393 eq (not executed by any Docker-free check): `===` -> `!==` in `type === "sbom" && p.sbomCompleteness !== null ? p.sbomCompleteness === "complete" : null,`

### apps/api/src/modules/reporting/policies/read.js

killed 0, survived 2, timeout 0, invalid 0

- `M0257` line 9 eq (not executed by any Docker-free check): `===` -> `!==` in `export const reportingEnabled = (config) => () => config?.reporting?.enabled === true;`
- `M0258` line 25 bool (not executed by any Docker-free check): `true` -> `false` in `select: { id: true },`

### apps/api/src/modules/reporting/read-cache.js

killed 4, survived 2, timeout 0, invalid 0

- `M0263` line 96 eq (not executed by any Docker-free check): `===` -> `!==` in `if (epoch === null) {`
- `M0264` line 114 int (not executed by any Docker-free check): `1` -> `2` in `stats.misses += 1;`

### apps/api/src/modules/reporting/read-client.js

killed 0, survived 2, timeout 0, invalid 0

- `M0265` line 17 negation (not executed by any Docker-free check): `!` -> `(removed)` in `if (!url) {`
- `M0266` line 19 bool (not executed by any Docker-free check): `true` -> `false` in `globalThis[KEY] = { warned: true };`

### apps/api/src/modules/reporting/read-repository.js

killed 0, survived 1, timeout 0, invalid 0

- `M0267` line 10 return-undefined (not executed by any Docker-free check): `return createReportingReadRepository({ db: lazy });` -> `return undefined;` in `return createReportingReadRepository({ db: lazy });`

### apps/api/src/modules/reporting/repositories/export.js

killed 0, survived 2, timeout 0, invalid 0

- `M0268` line 22 return-undefined (not executed by any Docker-free check): `return row?.reporting_timezone ?? "UTC";` -> `return undefined;` in `return row?.reporting_timezone ?? "UTC";`
- `M0269` line 41 eq (not executed by any Docker-free check): `===` -> `!==` in `if (userIds.length === 0) return new Map();`

### apps/api/src/modules/reporting/routes/export.routes.js

killed 0, survived 2, timeout 0, invalid 0

- `M0270` line 86 int (not executed by any Docker-free check): `200` -> `201` in `response: { 200: exportResponses.list },`
- `M0271` line 132 int (not executed by any Docker-free check): `200` -> `201` in `response: { 200: exportResponses.deleted },`

### apps/api/src/modules/reporting/routes/index.js

killed 0, survived 2, timeout 0, invalid 0

- `M0272` line 26 drop-call (not executed by any Docker-free check): `await reportingReadRoutes(deps)(app);` -> `;` in `await reportingReadRoutes(deps)(app);`
- `M0273` line 27 drop-call (not executed by any Docker-free check): `await reportingExportRoutes(deps)(app);` -> `;` in `await reportingExportRoutes(deps)(app);`

### apps/api/src/modules/reporting/routes/read.routes.js

killed 0, survived 2, timeout 0, invalid 0

- `M0274` line 49 int (not executed by any Docker-free check): `200` -> `201` in `response: { 200: readResponses.posture },`
- `M0275` line 155 int (not executed by any Docker-free check): `200` -> `201` in `response: { 200: readResponses.sbom },`

### apps/api/src/modules/reporting/schemas/export.js

killed 1, survived 0, timeout 0, invalid 0


### apps/api/src/modules/reporting/schemas/read.js

killed 5, survived 0, timeout 0, invalid 0


### apps/api/src/modules/reporting/services/export.js

killed 8, survived 3, timeout 0, invalid 0

- ★ `M0284` line 38 bound: `>` -> `>=` in `visible.length > 0 &&`
- `M0291` line 152 bound (not executed by any Docker-free check): `>` -> `>=` in `: visible.length > 0 &&`
- `M0292` line 261 eq (not executed by any Docker-free check): `===` -> `!==` in `{ ...facts(row), ...(estimatedRows === null ? {} : { estimatedRows }) },`

### apps/api/src/modules/reporting/services/read.js

killed 0, survived 2, timeout 0, invalid 0

- `M0293` line 279 return-undefined (not executed by any Docker-free check): `return { data: toCoverageDto(raw) };` -> `return undefined;` in `return { data: toCoverageDto(raw) };`
- `M0294` line 443 eq (not executed by any Docker-free check): `===` -> `!==` in `for (const r of raw.findings.filter((x) => x.workspaceId === w.id)) {`

### apps/workers/src/reporting/dispatch.js

killed 3, survived 1, timeout 0, invalid 0

- `M0102` line 22 drop-element: `        "reporting worker: no handler for this message type (its part is not built yet)",` -> `(removed)` in `"reporting worker: no handler for this message type (its part is not built yet)",`

### apps/workers/src/reporting/export/csv-writer.js

killed 5, survived 11, timeout 0, invalid 0

- ★ `M0105` line 28 bool: `false` -> `true` in `export function csvColumnsFor(template, { includeAssignee = false } = {}) {`
- ★ `M0108` line 31 logic: `||` -> `&&` in `return t.csvColumns.filter((c) => !c.requiresPermission || includeAssignee);`
- ★ `M0109` line 36 eq: `===` -> `!==` in `if (column.type === "text" && typeof value === "string")`
- ★ `M0114` line 36 logic: `&&` -> `||` in `if (column.type === "text" && typeof value === "string")`
- ★ `M0115` line 36 eq: `===` -> `!==` in `if (column.type === "text" && typeof value === "string")`
- ★ `M0113` line 37 return-undefined: `return csvSafeCell(redactCredentialShapes(value));` -> `return undefined;` in `return csvSafeCell(redactCredentialShapes(value));`
- ★ `M0118` line 38 return-undefined: `return csvSafeCell(value);` -> `return undefined;` in `return csvSafeCell(value);`
- ★ `M0112` line 51 bool: `false` -> `true` in `export function createCsvStream({ columns, records, bom = false, onRow }) {`
- `M0110` line 58 bound: `>=` -> `>` in `if (buffer.length >= CHUNK_CHARS) {`
- `M0116` line 63 bound: `>` -> `>=` in `if (buffer.length > 0) yield Buffer.from(buffer, "utf8");`
- `M0117` line 65 bool: `false` -> `true` in `return Readable.from(generate(), { objectMode: false });`

### apps/workers/src/reporting/export/handler.js

killed 10, survived 4, timeout 0, invalid 0

- ★ `M0122` line 37 eq: `===` -> `!==` in `if (error?.name === "TimeoutError" || error?.name === "AbortError") return "timeout";`
- ★ `M0124` line 40 eq: `===` -> `!==` in `if (code === "57014" || /statement timeout|canceling statement/i.test(text)) return "timeout";`
- `M0132` line 153 negation (not executed by any Docker-free check): `!` -> `(removed)` in `if (!template?.v1 || !template.formats.includes(row.format))`
- `M0133` line 173 int (not executed by any Docker-free check): `1` -> `2` in `written += 1;`

### apps/workers/src/reporting/export/index.js

killed 0, survived 2, timeout 0, invalid 0

- `M0134` line 25 negation (not executed by any Docker-free check): `!` -> `(removed)` in `if (!root) {`
- `M0135` line 44 drop-element (not executed by any Docker-free check): `        "reporting export: the retention pass failed",` -> `(removed)` in `"reporting export: the retention pass failed",`

### apps/workers/src/reporting/export/object-store.js

killed 16, survived 6, timeout 0, invalid 0

- ★ `M0137` line 30 logic: `||` -> `&&` in `typeof tenantId !== "string" ||`
- `M0141` line 72 drop-call: `await mkdir(base, { recursive: true, mode: 0o700 });` -> `;` in `await mkdir(base, { recursive: true, mode: 0o700 });`
- ★ `M0143` line 80 bound: `>` -> `>=` in `if (bytes > maxBytes) return callback(new ArtifactTooLargeError(maxBytes));`
- ★ `M0154` line 89 bool: `true` -> `false` in `await rm(temp, { force: true });`
- `M0156` line 101 return-undefined (not executed by any Docker-free check): `return info?.isFile() ? info.size : null;` -> `return undefined;` in `return info?.isFile() ? info.size : null;`
- `M0157` line 106 bool (not executed by any Docker-free check): `true` -> `false` in `await rm(locate(ref).file, { force: true });`

### apps/workers/src/reporting/export/pdf-kit.js

killed 6, survived 16, timeout 0, invalid 0

- ★ `M0160` line 87 bound: `>=` -> `>` in `if (cp >= 0x20 && cp <= 0x7e) out += ch;`
- ★ `M0161` line 87 logic: `&&` -> `||` in `if (cp >= 0x20 && cp <= 0x7e) out += ch;`
- ★ `M0168` line 87 bound: `<=` -> `<` in `if (cp >= 0x20 && cp <= 0x7e) out += ch;`
- ★ `M0169` line 88 logic: `&&` -> `||` in `else if (cp >= 0xa0 && cp <= 0xff) out += ch;`
- ★ `M0176` line 88 bound: `>=` -> `>` in `else if (cp >= 0xa0 && cp <= 0xff) out += ch;`
- ★ `M0162` line 90 eq: `===` -> `!==` in `else if (cp === 0x09 || cp === 0x0a || cp === 0x0d || cp === 0x20) out += " ";`
- ★ `M0170` line 90 eq: `===` -> `!==` in `else if (cp === 0x09 || cp === 0x0a || cp === 0x0d || cp === 0x20) out += " ";`
- ★ `M0177` line 90 logic: `||` -> `&&` in `else if (cp === 0x09 || cp === 0x0a || cp === 0x0d || cp === 0x20) out += " ";`
- `M0171` line 100 return-undefined: `return lum < 150;` -> `return undefined;` in `return lum < 150;`
- `M0164` line 122 bool: `true` -> `false` in `bufferPages: true,`
- `M0172` line 123 bool: `false` -> `true` in `autoFirstPage: false,`
- `M0174` line 161 drop-call: `doc.moveDown(0.2);` -> `;` in `doc.moveDown(0.2);`
- `M0165` line 338 minmax: `max` -> `min` in `const max = Math.max(1, ...bars.map((b) => b.value));`
- `M0173` line 347 minmax: `max` -> `min` in `const w = bar.value > 0 ? Math.max(2, (bar.value / max) * areaW) : 0;`
- `M0178` line 372 int (not executed by any Docker-free check): `18` -> `19` in `const h = categories.length * (barH + gap) + (chartTitle ? 18 : 4) + 18;`
- `M0179` line 542 int (not executed by any Docker-free check): `10` -> `11` in `return 10 * p;`

### apps/workers/src/reporting/export/retention.js

killed 0, survived 2, timeout 0, invalid 0

- `M0180` line 23 drop-call (not executed by any Docker-free check): `await store.delete({ tenantId, reportId: id, format });` -> `;` in `await store.delete({ tenantId, reportId: id, format });`
- `M0181` line 32 return-undefined (not executed by any Docker-free check): `return { expired: keys.length, removed };` -> `return undefined;` in `return { expired: keys.length, removed };`

### apps/workers/src/reporting/export/templates.js

killed 3, survived 2, timeout 0, invalid 0

- `M0185` line 317 drop-call (not executed by any Docker-free check): `kit.heading("Open findings by severity");` -> `;` in `kit.heading("Open findings by severity");`
- `M0186` line 386 int (not executed by any Docker-free check): `3` -> `4` in `{ key: "due", header: "Was due", width: 3 },`

### apps/workers/src/reporting/index.js

killed 2, survived 2, timeout 0, invalid 0

- `M0189` line 45 eq (not executed by any Docker-free check): `===` -> `!==` in `if (restricted === undefined) {`
- `M0190` line 85 drop-call (not executed by any Docker-free check): `await worker.stop();` -> `;` in `await worker.stop();`

### apps/workers/src/reporting/rollup/handler.js

killed 0, survived 2, timeout 0, invalid 0

- `M0191` line 28 eq (not executed by any Docker-free check): `!==` -> `===` in `if (config?.reporting && config.reporting.enabled !== true) {`
- `M0192` line 31 drop-element (not executed by any Docker-free check): `        "reporting is disabled: the rollup message is ignored, nothing is written",` -> `(removed)` in `"reporting is disabled: the rollup message is ignored, nothing is written",`

### apps/workers/src/reporting/rollup/index.js

killed 0, survived 2, timeout 0, invalid 0

- `M0193` line 26 return-undefined (not executed by any Docker-free check): `return buildRollupHandler(deps);` -> `return undefined;` in `return buildRollupHandler(deps);`
- `M0194` line 36 return-undefined (not executed by any Docker-free check): `return buildRollupTick(deps);` -> `return undefined;` in `return buildRollupTick(deps);`

### apps/workers/src/reporting/rollup/job.js

killed 6, survived 2, timeout 0, invalid 0

- `M0201` line 227 bool (not executed by any Docker-free check): `true` -> `false` in `zeroExecutions: true,`
- `M0202` line 254 bound (not executed by any Docker-free check): `>` -> `>=` in `if (start > end) return { batches: 0, skipped: 0, rowsWritten: 0 };`

### apps/workers/src/reporting/rollup/tick.js

killed 10, survived 2, timeout 0, invalid 0

- `M0213` line 102 quantifier (not executed by any Docker-free check): `some` -> `every` in `if (!closes.some((r) => r.status === "succeeded" && r.day === yesterday)) {`
- `M0214` line 133 int (not executed by any Docker-free check): `1` -> `2` in `after = page[page.length - 1].tenantId;`

### packages/db/src/reporting/exports/api-methods.js

killed 0, survived 2, timeout 0, invalid 0

- `M0295` line 78 bound (not executed by any Docker-free check): `>` -> `>=` in `rows.length > limit && last`
- `M0296` line 90 eq (not executed by any Docker-free check): `===` -> `!==` in `if (done.count === 0) return null;`

### packages/db/src/reporting/exports/datasets.js

killed 1, survived 2, timeout 0, invalid 0

- `M0298` line 71 eq (not executed by any Docker-free check): `===` -> `!==` in `distinct: params.distinctIssues === true,`
- `M0299` line 475 return-undefined (not executed by any Docker-free check): `return { rows, next: null };` -> `return undefined;` in `return { rows, next: null };`

### packages/db/src/reporting/exports/mappers.js

killed 0, survived 2, timeout 0, invalid 0

- `M0300` line 8 eq (not executed by any Docker-free check): `===` -> `!==` in `if (value === null || value === undefined) return null;`
- `M0301` line 41 eq (not executed by any Docker-free check): `===` -> `!==` in `bytes: bytes === null || bytes === undefined ? null : Number(bytes),`

### packages/db/src/reporting/exports/worker-methods.js

killed 0, survived 2, timeout 0, invalid 0

- `M0302` line 38 return-undefined (not executed by any Docker-free check): `return { ...mapped, timeZone: zone?.reporting_timezone ?? "UTC" };` -> `return undefined;` in `return { ...mapped, timeZone: zone?.reporting_timezone ?? "UTC" };`
- `M0303` line 93 bound (not executed by any Docker-free check): `>` -> `>=` in `return changed > 0;`

### packages/db/src/reporting/index.js

killed 10, survived 0, timeout 0, invalid 0


### packages/db/src/reporting/not-implemented.js

killed 2, survived 0, timeout 0, invalid 0


### packages/db/src/reporting/read/breakdown-metrics.js

killed 0, survived 2, timeout 0, invalid 0

- `M0316` line 86 bound (not executed by any Docker-free check): `>` -> `>=` in `next: rows.length > take && last ? { open: last.open, key: last.key } : null,`
- `M0317` line 107 return-undefined (not executed by any Docker-free check): `return rankRepositories(rows).slice(0, take);` -> `return undefined;` in `return rankRepositories(rows).slice(0, take);`

### packages/db/src/reporting/read/findings-metrics.js

killed 0, survived 2, timeout 0, invalid 0

- `M0318` line 145 logic (not executed by any Docker-free check): `&&` -> `||` in `stats(r1.find((r) => cnt(r.overall) === 0 && r.severity === sev)),`
- `M0319` line 163 eq (not executed by any Docker-free check): `===` -> `!==` in `stats(r3.find((r) => cnt(r.overall) === 0 && r.scanType === t)),`

### packages/db/src/reporting/read/posture.js

killed 0, survived 2, timeout 0, invalid 0

- `M0320` line 23 drop-call (not executed by any Docker-free check): `uuid("tenantId", tenantId);` -> `;` in `uuid("tenantId", tenantId);`
- `M0321` line 116 eq (not executed by any Docker-free check): `===` -> `!==` in `if (runs.length === 0) return null;`

### packages/db/src/reporting/read/quality-metrics.js

killed 0, survived 2, timeout 0, invalid 0

- `M0322` line 14 drop-call (not executed by any Docker-free check): `uuid("workspaceId", workspaceId);` -> `;` in `uuid("workspaceId", workspaceId);`
- `M0323` line 15 drop-call (not executed by any Docker-free check): `day("from", from);` -> `;` in `day("from", from);`

### packages/db/src/reporting/read/scan-metrics.js

killed 0, survived 2, timeout 0, invalid 0

- `M0324` line 149 drop-call (not executed by any Docker-free check): `day("to", to);` -> `;` in `day("to", to);`
- `M0325` line 177 logic (not executed by any Docker-free check): `||` -> `&&` in `ecosystem: r.ecosystem || "unknown",`

### packages/db/src/reporting/read/tx.js

killed 2, survived 2, timeout 0, invalid 0

- `M0328` line 28 eq (not executed by any Docker-free check): `===` -> `!==` in `export const num = (v) => (v === null || v === undefined ? null : Number(v));`
- `M0329` line 63 int (not executed by any Docker-free check): `30000` -> `30001` in `{ maxWait: 5000, timeout: 30000 },`

### packages/db/src/reporting/rollup/flow.js

killed 0, survived 2, timeout 0, invalid 0

- `M0330` line 75 bool (not executed by any Docker-free check): `false` -> `true` in `enumerable: false,`
- ★ `M0331` line 207 drop-call (not executed by any Docker-free check): `assertUuid(tenantId, "tenantId");` -> `;` in `assertUuid(tenantId, "tenantId");`

### packages/db/src/reporting/rollup/runs.js

killed 0, survived 2, timeout 0, invalid 0

- `M0332` line 117 eq (not executed by any Docker-free check): `!==` -> `===` in `if (asOfHistoryId !== null) assertUuid(asOfHistoryId, "asOfHistoryId");`
- `M0333` line 157 return-undefined (not executed by any Docker-free check): `return rows.map(runOf);` -> `return undefined;` in `return rows.map(runOf);`

### packages/db/src/reporting/rollup/state.js

killed 0, survived 2, timeout 0, invalid 0

- `M0334` line 43 logic (not executed by any Docker-free check): `||` -> `&&` in `if (!(instant instanceof Date) || Number.isNaN(instant.getTime()))`
- `M0335` line 116 return-undefined (not executed by any Docker-free check): `return { rows, newest };` -> `return undefined;` in `return { rows, newest };`

### packages/db/src/reporting/rollup/store.js

killed 0, survived 3, timeout 0, invalid 0

- `M0337` line 71 eq (not executed by any Docker-free check): `!==` -> `===` in `if (!row || typeof row !== "object")`
- `M0338` line 177 drop-call (not executed by any Docker-free check): `flow.push(toJson(tenantId, row, FINDINGS_FLOW, { scanType: true, severity: true }));` -> `;` in `flow.push(toJson(tenantId, row, FINDINGS_FLOW, { scanType: true, severity: true }));`
- `M0336` line 232 bool: `true` -> `false` in `{ scanType: true },`

### packages/db/src/reporting/rollup/util.js

killed 2, survived 2, timeout 0, invalid 0

- `M0341` line 38 return-undefined (not executed by any Docker-free check): `return value;` -> `return undefined;` in `return value;`
- `M0342` line 42 eq (not executed by any Docker-free check): `===` -> `!==` in `export const num = (value) => (value === null || value === undefined ? 0 : Number(value));`

### packages/shared/src/reporting/constants.js

killed 10, survived 0, timeout 0, invalid 0


### packages/shared/src/reporting/csv.js

killed 12, survived 1, timeout 0, invalid 0

- ★ `M0015` line 38 logic: `||` -> `&&` in `const dangerous = first === "\t" || first === "\r" || FORMULA_START_RE.test(text);`

### packages/shared/src/reporting/metrics.js

killed 10, survived 0, timeout 0, invalid 0


### packages/shared/src/reporting/period.js

killed 14, survived 8, timeout 0, invalid 0

- `M0043` line 42 drop-call: `formatters.set(timeZone, f);` -> `;` in `formatters.set(timeZone, f);`
- ★ `M0038` line 53 logic: `||` -> `&&` in `if (typeof timeZone !== "string" || timeZone.length === 0 || timeZone.length > 64) return false;`
- ★ `M0039` line 53 bound: `>` -> `>=` in `if (typeof timeZone !== "string" || timeZone.length === 0 || timeZone.length > 64) return false;`
- ★ `M0040` line 53 int: `64` -> `65` in `if (typeof timeZone !== "string" || timeZone.length === 0 || timeZone.length > 64) return false;`
- ★ `M0047` line 53 logic: `||` -> `&&` in `if (typeof timeZone !== "string" || timeZone.length === 0 || timeZone.length > 64) return false;`
- ★ `M0054` line 53 bool (not executed by any Docker-free check): `false` -> `true` in `if (typeof timeZone !== "string" || timeZone.length === 0 || timeZone.length > 64) return false;`
- `M0055` line 54 bool (not executed by any Docker-free check): `false` -> `true` in `if (!ZONE_RE.test(timeZone)) return false;`
- `M0042` line 222 drop-element: `        "from and to must both be YYYY-MM-DD days",` -> `(removed)` in `"from and to must both be YYYY-MM-DD days",`

### packages/shared/src/reporting/risk.js

killed 13, survived 6, timeout 0, invalid 0

- `M0059` line 21 bound: `>` -> `>=` in `const n = (v) => (typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : 0);`
- `M0064` line 43 bound: `<` -> `<=` in `if (ta !== tb) return ta < tb ? -1 : 1;`
- `M0071` line 43 int: `1` -> `2` in `if (ta !== tb) return ta < tb ? -1 : 1;`
- `M0072` line 43 int: `1` -> `2` in `if (ta !== tb) return ta < tb ? -1 : 1;`
- `M0073` line 44 int: `1` -> `2` in `return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;`
- `M0074` line 44 int: `1` -> `2` in `return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;`

### packages/shared/src/reporting/schemas.js

killed 12, survived 2, timeout 0, invalid 1

- `M0088` line 187 logic (not executed by any Docker-free check): `||` -> `&&` in `const hasRange = v.from !== undefined || v.to !== undefined;`
- `M0089` line 193 logic (not executed by any Docker-free check): `&&` -> `||` in `if (t.periodMode !== "period" && hasPeriod)`

### packages/shared/src/reporting/templates.js

killed 10, survived 0, timeout 0, invalid 0




### 3.2 Database pass (19 survivors)

- ★ `packages/db/src/reporting/exports/datasets.js` line 72 bool: `assignee: params.includeAssignee === true,`
- ★ `packages/db/src/reporting/exports/worker-methods.js` line 75 logic: `if (!OBJECT_KEY.test(objectKey) || !objectKey.includes(`/${tenantId}/${id}.`))`
- `packages/db/src/reporting/read/findings-metrics.js` line 66 drop-call: `day("from", from);`
- ★ `packages/db/src/reporting/read/findings-metrics.js` line 171 drop-call: `uuid("tenantId", tenantId);`
- ★ `packages/db/src/reporting/read/posture.js` line 44 drop-call: `uuid("tenantId", tenantId);`
- ★ `packages/db/src/reporting/read/posture.js` line 45 drop-call: `uuid("workspaceId", workspaceId);`
- `packages/db/src/reporting/read/quality-metrics.js` line 81 int: `falsePositiveShare: Math.min(1, Math.max(0, num(r.share) ?? 0)),`
- `packages/db/src/reporting/read/quality-metrics.js` line 81 minmax: `falsePositiveShare: Math.min(1, Math.max(0, num(r.share) ?? 0)),`
- ★ `packages/db/src/reporting/read/scan-metrics.js` line 70 drop-call: `uuid("workspaceId", workspaceId);`
- `apps/api/src/modules/reporting/mappers/read.js` line 238 bound: `return days.length > 0 ? { days, label: /** @type {const} */ ("estimate") } : null;`
- `apps/api/src/modules/reporting/mappers/read.js` line 393 eq: `type === "sbom" && p.sbomCompleteness !== null ? p.sbomCompleteness === "complete" : null,`
- `apps/api/src/modules/reporting/repositories/export.js` line 22 return-undefined: `return row?.reporting_timezone ?? "UTC";`
- `apps/api/src/modules/reporting/services/read.js` line 169 bool: `rollup: true,`
- `apps/api/src/modules/reporting/services/read.js` line 336 logic: `!Number.isInteger(after.open) ||`
- `apps/workers/src/reporting/rollup/job.js` line 181 bool: `zeroExecutions: true,`
- ★ `packages/db/src/reporting/rollup/flow.js` line 147 drop-call: `assertUuid(tenantId, "tenantId");`
- ★ `packages/db/src/reporting/rollup/flow.js` line 207 drop-call: `assertUuid(tenantId, "tenantId");`
- ★ `packages/db/src/reporting/rollup/runs.js` line 45 logic: `if (!Number.isInteger(limit) || limit < 1 || limit > 1000)`
- ★ `packages/db/src/reporting/rollup/runs.js` line 82 logic: `(rangeTo !== null && (!DAY.test(rangeTo) || rangeTo < day))`

## 4. Starred survivors killed in this part (`RPT-SM01` to `RPT-SM06`)

All of these checks are database-free except where stated, so they also run in the memory pass of any later sweep. Each row was re-run with `mutation-sweep.js one --only RPT-SM`.

| Line (starred) | Property | Killed by | Residue after the re-run |
|---|---|---|---|
| `shared/reporting/csv.js` 38 | a cell that starts with a tab or a carriage return alone is neutralised | `RPT-SM01` | none |
| `api/reporting/export-object-reader.js` 24, `workers/.../object-store.js` 30 | the object key is built only from strings (an array or an object that prints as a UUID is refused) | `RPT-SM02` | none |
| `object-store.js` 80, 89 | the size cap is exact (one byte more is refused); a refused file leaves no temporary file | `RPT-SM02` | 89 `true` to `false` (`rm` with `force`: a missing temp file, equivalent) |
| `csv-writer.js` 28, 31, 37, 38, 51 | the assignee column only for a holder of `finding.assign`; text cells redacted AND neutralised; the BOM only when asked | `RPT-SM01` | 36 `&&` to `||` (a non-string text cell still passes `csvSafeCell`; equivalent) |
| `pdf-kit.js` 87, 88, 90 | `pdfText` keeps printable ASCII and Latin-1, folds white space, replaces everything else | `RPT-SM03` | 87 `>=` to `>` (the space is handled by the white-space branch, equivalent) and three `||` to `&&` on line 90 (the redactor already turns control characters into spaces, equivalent) |
| `export-authorization.js` 21, 76, 117 | each gate calls the next handler exactly once or refuses | `RPT-SM04` | none |
| `services/export.js` 38 | a tenant-wide export needs at least one visible workspace | `RPT-SM04` | none |
| `workers/.../handler.js` 37, 40 | the stable failure codes | `RPT-SM03` | none |
| `shared/reporting/period.js` 53 | time zone validation | `RPT-SM03` | `||` to `&&`, `>` to `>=`, `64` to `65` (the zone pattern and `Intl` refuse an over-long name anyway; equivalent) |
| `db/reporting/read/posture.js` 44, 45, `findings-metrics.js` 171, `scan-metrics.js` 70, `rollup/flow.js` 147, 207 | tenant and workspace ids are validated before any statement (database pass survivors) | `RPT-SM05` | none |
| `db/reporting/rollup/runs.js` 45, 82 | page size and run range bounds | `RPT-SM05` | none |
| `db/reporting/exports/worker-methods.js` 75 | `completeExport` accepts only the exact key of THAT tenant and report | `RPT-SM06` | none |
| `db/reporting/exports/datasets.js` 72 | the assignee name is selected only for `includeAssignee: true` | `RPT-SM06` | none |

Net: of the 43 starred survivors, 34 were killed and 9 are residue judged equivalent in the table (kill rate on the starred set after Part E: 34 of 43 survivors converted, the 9 left are not security-relevant on inspection but are listed so that the owner can disagree).

## 5. Defects found and observations (see also `AS_BUILT_E.md` section 6)

- **D-E1 (low):** the export handler has no `REPORTING_ENABLED` guard (the rollup handler has one). With the flag off the worker entry starts nothing, so no export message is consumed, and the routes answer 404, so no `report_exports` row can be created; but a queued row left from before the flag was turned off would be processed if a message arrived. Patch proposal in `AS_BUILT_E.md` 6. Not patched (outside the three named fixes).
- `findings-metrics.js` line 66 (`day("from", from)` in `getTrends`) survived the re-run: a malformed day reaches the database cast, which refuses it, so the check is a duplicate of the statement's own error, not a gap in tenant scope.
