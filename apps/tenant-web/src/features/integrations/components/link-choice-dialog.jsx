import { Download, Search } from "lucide-react";
import { Button } from "@/components/ui/button.jsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog.jsx";

/**
 * The two ways to link a GitHub account (T-42): install the App on an account (opens GitHub's install page) or use an
 * installation of the App that already exists on an account the user administers (discovery, SPEC §16.2).
 * @param {{ open: boolean, onOpenChange: (open: boolean) => void, onInstall: () => void, onUseExisting: () => void, pending?: boolean }} props
 */
export function LinkChoiceDialog({ open, onOpenChange, onInstall, onUseExisting, pending }) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Link a GitHub account</DialogTitle>
          <DialogDescription>
            Choose how to connect GitHub to this workspace. You must be an owner of the
            organization.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <Button
            variant="secondary"
            className="h-auto justify-start gap-3 whitespace-normal p-3 text-left"
            onClick={onInstall}
            disabled={pending}
          >
            <Download aria-hidden="true" />
            <span className="grid">
              <span className="font-medium">Install the App on a GitHub account</span>
              <span className="text-xs font-normal text-muted-foreground">
                Opens GitHub, where you choose the account and repositories.
              </span>
            </span>
          </Button>
          <Button
            variant="secondary"
            className="h-auto justify-start gap-3 whitespace-normal p-3 text-left"
            onClick={onUseExisting}
            disabled={pending}
          >
            <Search aria-hidden="true" />
            <span className="grid">
              <span className="font-medium">Use an existing installation</span>
              <span className="text-xs font-normal text-muted-foreground">
                The App is already installed: pick one of the accounts you administer.
              </span>
            </span>
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
