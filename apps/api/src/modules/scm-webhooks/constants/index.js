export const MODULE_NAME = "scm-webhooks";
export const API_PREFIX = "/api/v1";
export const OPENAPI_TAG = "Webhooks";
export const DELIVERY_ID = /^[A-Za-z0-9._-]{8,128}$/;
export const EVENT_NAME = /^[a-z_]{1,64}$/;
export const PULL_REQUEST_ACTIONS = new Set([
  "opened",
  "reopened",
  "synchronize",
  "closed",
  "edited",
  "ready_for_review",
  "converted_to_draft",
]);
export const REPOSITORY_ACTIONS = new Set([
  "renamed",
  "edited",
  "archived",
  "unarchived",
  "privatized",
  "publicized",
  "transferred",
]);
