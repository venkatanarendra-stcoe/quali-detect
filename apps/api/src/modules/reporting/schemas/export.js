import { createSuccessSchema } from "@qmentisai/contracts";
import {
  createReportResponseSchema,
  listReportsDtoSchema,
  reportRunDtoSchema,
} from "@qmentisai/shared";
import { z } from "zod";

/** `POST /reporting/reports` REQUIRES the key (SPEC 9); the route kit's idempotency middleware validates the same pattern and scopes it. */
export const createReportHeadersSchema = z
  .object({ "idempotency-key": z.string().regex(/^[A-Za-z0-9._:-]{8,128}$/) })
  .passthrough();

/** Documented responses of the export routes (the data schemas are the frozen ones of `@qmentisai/shared`). */
export const exportResponses = Object.freeze({
  create: createSuccessSchema(createReportResponseSchema),
  one: createSuccessSchema(reportRunDtoSchema),
  list: createSuccessSchema(listReportsDtoSchema),
  deleted: createSuccessSchema(z.object({ deleted: z.literal(true) }).strict()),
});
