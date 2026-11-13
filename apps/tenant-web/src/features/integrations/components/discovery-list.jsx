import { Building2, CircleCheck, PauseCircle, User } from "lucide-react";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";

const SUSPENDED = "Suspended on GitHub: unsuspend it there first";
const NOT_OWNER = "Only an owner of the organization can link it";

/**
 * Installations of the App that the signed-in GitHub user can see (SPEC §16.2). Rows that cannot be chosen are disabled with
 * the reason shown in text. Choosing one starts the normal linking flow with that installation id.
 * @param {{ candidates: Array<any>, pending?: boolean, onChoose: (externalInstallationId: string) => void }} props
 */
export function DiscoveryList({ candidates, pending, onChoose }) {
  return (
    <>
      <ul className="space-y-2" aria-label="Installations of the App on your GitHub accounts">
        {candidates.map((c) => {
          const Icon = c.account.type === "organization" ? Building2 : User;
          const blocked = c.alreadyLinkedHere || !c.eligible || c.suspended;
          const note = c.alreadyLinkedHere
            ? "Already linked here"
            : c.suspended
              ? SUSPENDED
              : c.eligible
                ? null
                : NOT_OWNER;
          return (
            <li
              key={c.externalInstallationId}
              className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-border p-3"
            >
              <div className="flex min-w-0 flex-wrap items-center gap-2">
                <Icon aria-hidden="true" className="size-4 text-muted-foreground" />
                <span className="font-mono text-sm font-semibold">{c.account.login}</span>
                <Badge>
                  {c.account.type === "organization" ? "Organization" : "Personal account"}
                </Badge>
                <Badge>
                  {c.repositorySelection === "all" ? "All repositories" : "Selected repositories"}
                </Badge>
                {c.suspended ? (
                  <Badge tone="warning">
                    <PauseCircle aria-hidden="true" />
                    Suspended
                  </Badge>
                ) : null}
                {c.alreadyLinkedHere ? (
                  <Badge tone="success">
                    <CircleCheck aria-hidden="true" />
                    Already linked here
                  </Badge>
                ) : null}
              </div>
              <div className="flex items-center gap-3">
                {note && !c.alreadyLinkedHere ? (
                  <span className="text-xs text-muted-foreground">{note}</span>
                ) : null}
                <Button
                  variant="secondary"
                  disabled={blocked || pending}
                  aria-label={`Use the installation on ${c.account.login}`}
                  onClick={() => onChoose(c.externalInstallationId)}
                >
                  Use this installation
                </Button>
              </div>
            </li>
          );
        })}
      </ul>
      <p className="mt-3 text-xs text-muted-foreground">
        An installation that was uninstalled on GitHub is not listed (it is revoked). Install the
        App again from this workspace&apos;s Integrations page instead.
      </p>
    </>
  );
}
