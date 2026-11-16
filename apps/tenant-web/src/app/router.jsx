import { BrowserRouter, Navigate, Route, Routes } from "react-router";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import {
  LoginPage,
  PublicOnly,
  RequireAuth,
  RequireTenant,
  SelectTenantPage,
} from "@/features/auth/index.js";
import { AccountPage, SettingsPage } from "@/features/account/index.js";
import { RequirePermission } from "@/features/authorization/index.js";
import { ExecutionAliasRedirect } from "@/features/executions/index.js";
import { PipelineAliasRedirect } from "@/features/pipelines/index.js";
import { ConnectAliasRedirect, RepositoryAliasRedirect } from "@/features/repositories/index.js";
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
              {/* Own account: any signed-in user, no permission (preferences are the user's own). */}
              <Route path="account" element={<AccountPage />} />
              <Route path="my-settings" element={<SettingsPage />} />
              <Route path="account/settings" element={<Navigate to="/my-settings" replace />} />
              {ORG_ROUTES.map((r) => (
                <Route key={r.path} path={r.path} element={guarded(r)} />
              ))}
              <Route path="repositories" element={<LegacyRepositoriesRedirect />} />
              <Route path="repositories/connect" element={<ConnectAliasRedirect />} />
              <Route path="repositories/:repositoryId" element={<RepositoryAliasRedirect />} />
              <Route path="pipelines" element={<PipelineAliasRedirect kind="list" />} />
              <Route path="pipelines/new" element={<PipelineAliasRedirect kind="new" />} />
              <Route
                path="pipelines/:pipelineId"
                element={<PipelineAliasRedirect kind="detail" />}
              />
              <Route
                path="pipelines/:pipelineId/edit"
                element={<PipelineAliasRedirect kind="edit" />}
              />
              <Route path="executions" element={<ExecutionAliasRedirect kind="list" />} />
              <Route
                path="executions/:executionId"
                element={<ExecutionAliasRedirect kind="detail" />}
              />
              <Route path="workspaces/:workspaceId" element={<WorkspaceScope />}>
                <Route index element={<Navigate to="dashboard" replace />} />
                <Route path="edit" element={<Navigate to="../settings" replace />} />
                {WORKSPACE_ROUTES.map((r) => (
                  <Route
                    key={r.path}
                    path={r.path}
                    element={guarded({ scope: "workspace", ...r })}
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
