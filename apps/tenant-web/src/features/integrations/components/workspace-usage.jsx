/** Workspaces using an installation: names the caller can see plus a count for the rest. */
export function WorkspaceUsage({ installation }) {
  const { workspaces, hiddenWorkspaceCount, workspaceCount } = installation;
  if (workspaceCount === 0)
    return <span className="text-muted-foreground">Not used by any workspace</span>;
  return (
    <span>
      {workspaces.map((w) => w.name).join(", ")}
      {hiddenWorkspaceCount > 0 ? (
        <span className="text-muted-foreground">
          {workspaces.length > 0 ? ", " : ""}+{hiddenWorkspaceCount} more
        </span>
      ) : null}
    </span>
  );
}
