import { useState } from "react";
import { toast } from "sonner";
import { SearchPicker } from "@/components/common/search-picker.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Select } from "@/components/ui/select.jsx";
import { useCan } from "@/features/authorization/hooks/use-permissions.js";
import {
  useAssignableRoles,
  useGroupSearch,
  useUserSearch,
} from "@/features/directory/hooks/use-directory.js";
import { useDebouncedValue } from "@/hooks/use-debounced-value.js";
import { describeError, isApiError } from "@/lib/api/index.js";
import { useCreateAssignment } from "../hooks/use-workspaces.js";

/** Server refusals that deserve a plain-language explanation. */
function explain(error) {
  if (isApiError(error) && error.code === "ROLE_ESCALATION")
    return "You can't grant permissions that you don't hold yourself. Choose a role within your own access.";
  if (isApiError(error) && error.status === 409)
    return "This person or group already has this role in the workspace.";
  return describeError(error);
}

function AddAccessBody({ workspace, onClose }) {
  const can = useCan();
  const [kind, setKind] = useState("person");
  const [query, setQuery] = useState("");
  const [subject, setSubject] = useState(null);
  const [roleId, setRoleId] = useState("");
  const [expires, setExpires] = useState("");
  const [error, setError] = useState(null);
  const debounced = useDebouncedValue(query);
  const roles = useAssignableRoles();
  const people = useUserSearch(debounced, { enabled: kind === "person" });
  const groups = useGroupSearch(debounced, { enabled: kind === "group" && can("group.view") });
  const source = kind === "person" ? people : groups;
  const options = (source.data ?? []).map((item) =>
    kind === "person"
      ? { id: item.userId, label: item.name ?? item.email, hint: item.email }
      : {
          id: item.id,
          label: item.name,
          hint: `${item.memberCount} ${item.memberCount === 1 ? "member" : "members"}`,
        },
  );
  const create = useCreateAssignment(workspace.id);

  const submit = async (event) => {
    event.preventDefault();
    setError(null);
    try {
      await create.mutateAsync({
        subjectType: kind === "person" ? "user" : "group",
        subjectId: subject.id,
        roleId,
        ...(expires ? { expiresAt: new Date(expires).toISOString() } : {}),
      });
      toast.success(`Access granted to ${subject.label}`);
      onClose();
    } catch (e) {
      setError(e);
    }
  };

  return (
    <DialogContent>
      <form onSubmit={submit} className="space-y-4">
        <DialogHeader>
          <DialogTitle>Add access to {workspace.name}</DialogTitle>
          <DialogDescription>
            Give a person or a group a role in this workspace. The role decides what they can do;
            being listed alone grants nothing.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <Label htmlFor="add-kind">Add</Label>
          <Select
            id="add-kind"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value);
              setSubject(null);
              setQuery("");
            }}
          >
            <option value="person">Person</option>
            <option value="group" disabled={!can("group.view")}>
              Group{can("group.view") ? "" : " (needs group access)"}
            </option>
          </Select>
        </div>
        <SearchPicker
          id="add-subject"
          label={kind === "person" ? "Person" : "Group"}
          placeholder={kind === "person" ? "Search by name or email" : "Search groups"}
          query={query}
          onQueryChange={setQuery}
          options={options}
          isLoading={source.isFetching}
          error={source.error}
          selected={subject}
          onSelect={setSubject}
          onClear={() => setSubject(null)}
        />
        <div className="space-y-1.5">
          <Label htmlFor="add-role">Workspace role</Label>
          <Select
            id="add-role"
            value={roleId}
            onChange={(e) => setRoleId(e.target.value)}
            disabled={roles.isPending}
          >
            <option value="">{roles.isPending ? "Loading roles…" : "Choose a role"}</option>
            {(roles.data ?? []).map((role) => (
              <option key={role.id} value={role.id}>
                {role.name}
              </option>
            ))}
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="add-expires">
            Expires <span className="font-normal text-muted-foreground">(optional)</span>
          </Label>
          <Input
            id="add-expires"
            type="datetime-local"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
          />
        </div>
        {error ? (
          <p role="alert" className="text-sm text-status-danger">
            {explain(error)}
          </p>
        ) : null}
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" disabled={!subject || !roleId || create.isPending}>
            {create.isPending ? "Adding…" : "Add access"}
          </Button>
        </DialogFooter>
      </form>
    </DialogContent>
  );
}

/** Dialog to grant a role in one workspace. The body remounts on every open so no stale selection survives. */
export function AddAccessDialog({ workspace, open, onOpenChange }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      {open ? <AddAccessBody workspace={workspace} onClose={() => onOpenChange(false)} /> : null}
    </Dialog>
  );
}
