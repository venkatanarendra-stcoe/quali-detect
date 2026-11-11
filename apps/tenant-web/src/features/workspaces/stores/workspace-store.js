import { create } from "zustand";
import { persist, createJSONStorage } from "zustand/middleware";
import { safeStorage } from "@/lib/safe-storage.js";

/**
 * Workspace selection (client state): the last workspace opened, remembered PER TENANT so a legacy URL such as
 * `/repositories` can pick "the last or first accessible workspace". The server stays the source of which workspaces
 * exist; a remembered id that is no longer accessible is ignored by the caller.
 */
export const useWorkspaceStore = create()(
  persist(
    (set) => ({
      lastWorkspaceByTenant: {},
      rememberWorkspace: (tenantId, workspaceId) =>
        set((state) =>
          state.lastWorkspaceByTenant[tenantId] === workspaceId
            ? state
            : {
                lastWorkspaceByTenant: { ...state.lastWorkspaceByTenant, [tenantId]: workspaceId },
              },
        ),
    }),
    { name: "qm-workspace", storage: createJSONStorage(() => safeStorage) },
  ),
);
