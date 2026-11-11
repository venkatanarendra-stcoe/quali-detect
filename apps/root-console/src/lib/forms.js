import { isApiError } from "@/lib/api/index.js";

/**
 * Maps the API's field-level validation issues (`details.issues[{ path, message }]`) onto React Hook Form fields.
 * Returns true when at least one issue was applied (the caller then shows nothing else).
 * @param {unknown} error @param {(name: string, error: { message: string }) => void} setError @param {(path: string) => boolean} [isField]
 */
export function applyServerIssues(error, setError, isField = () => true) {
  if (!isApiError(error) || error.code !== "VALIDATION_FAILED") return false;
  let applied = false;
  for (const issue of error.details?.issues ?? []) {
    if (issue.path && isField(issue.path)) {
      setError(issue.path, { message: issue.message });
      applied = true;
    }
  }
  return applied;
}
