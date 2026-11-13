import { PIPELINE_SCAN_TYPES } from "@qmentisai/shared";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card.jsx";
import { SCAN_SHORT, TRIGGER_LABELS } from "../constants/index.js";

/** The Pipeline summary card next to the wizard (name, repository, enabled triggers and scans). */
export function WizardSummary({ name, repositoryName, config, editing, nextVersion }) {
  const triggers = config.triggers.filter((t) => t.enabled);
  const scans = PIPELINE_SCAN_TYPES.filter((t) => config.scans[t]?.enabled);
  return (
    <Card className="h-fit">
      <CardHeader>
        <CardTitle className="text-sm">Pipeline summary</CardTitle>
      </CardHeader>
      <CardContent>
        <dl className="space-y-2 text-sm">
          <div>
            <dt className="text-muted-foreground">Name</dt>
            <dd className="break-words">{name || "—"}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Repository</dt>
            <dd>
              {repositoryName ? (
                <span className="font-mono text-xs [overflow-wrap:anywhere]">{repositoryName}</span>
              ) : (
                "—"
              )}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Triggers</dt>
            <dd>
              {triggers.length ? triggers.map((t) => TRIGGER_LABELS[t.type]).join(", ") : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Scans</dt>
            <dd>{scans.length ? scans.map((s) => SCAN_SHORT[s]).join(", ") : "—"}</dd>
          </div>
          {editing ? (
            <div>
              <dt className="text-muted-foreground">Saves as</dt>
              <dd>Version {nextVersion}</dd>
            </div>
          ) : null}
        </dl>
      </CardContent>
    </Card>
  );
}
