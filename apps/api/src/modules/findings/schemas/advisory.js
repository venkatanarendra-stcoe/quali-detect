import { createSuccessSchema } from "@qmentisai/contracts";
import { advisoryDtoSchema } from "@qmentisai/shared";

/** Response of `POST /findings/{id}/advisory/request` (202): the advisory DTO in the standard envelope. */
export const advisoryResponses = Object.freeze({ request: createSuccessSchema(advisoryDtoSchema) });
