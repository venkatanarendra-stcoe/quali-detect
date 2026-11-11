import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import {
  LoginPage,
  PublicOnly,
  RequireAuth,
  RequireTenant,
  SelectTenantPage,
} from "@/features/auth/index.js";
import { RequirePermission } from "@/features/authorization/index.js";
import { WorkspaceScope } from "@/features/workspaces/index.js";
import { AppLayout } from "./layouts/app-layout.jsx";
import { LandingRedirect, LegacyRepositoriesRedirect } from "./landing.jsx";
import { ORG_ROUTES, WORKSPACE_ROUTES } from "./routes.jsx";

const guarded = ({ permission, scope, element }) => (
  <RequirePermission permission={permission} scope={scope}>
    {element}
  </RequirePermission>
);

/** Route tree: public login, authenticated routes, tenant-required application routes inside the shell. */
export function AppRouter() {
  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={
            <PublicOnly>
              <LoginPage />
            </PublicOnly>
          }
        />
        <Route element={<RequireAuth />}>
          <Route path="/select-tenant" element={<SelectTenantPage />} />
          <Route element={<RequireTenant />}>
            <Route element={<AppLayout />}>
              <Route index element={<LandingRedirect />} />
              {ORG_ROUTES.map((r) => (
                <Route key={r.path} path={r.path} element={guarded(r)} />
              ))}
              <Route path="repositories" element={<LegacyRepositoriesRedirect />} />
              <Route path="workspaces/:workspaceId" element={<WorkspaceScope />}>
                <Route index element={<Navigate to="dashboard" replace />} />
                <Route path="edit" element={<Navigate to="../settings" replace />} />
                {WORKSPACE_ROUTES.map((r) => (
                  <Route
                    key={r.path}
                    path={r.path}
                    element={guarded({ ...r, scope: "workspace" })}
                  />
                ))}
                <Route path="*" element={<NotFoundState />} />
              </Route>
              <Route path="*" element={<NotFoundState />} />
            </Route>
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
