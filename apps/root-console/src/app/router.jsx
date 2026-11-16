import { BrowserRouter, Route, Routes } from "react-router";
import { NotFoundState } from "@/components/states/not-found-state.jsx";
import {
  LoginPage,
  MfaOnly,
  MfaPage,
  PublicOnly,
  RequirePlatformAuth,
} from "@/features/auth/index.js";
import { AccountPage, SettingsPage } from "@/features/account/index.js";
import { RequirePlatformPermission } from "@/features/authorization/index.js";
import { AppLayout } from "./layouts/app-layout.jsx";
import { LandingRedirect } from "./landing.jsx";
import { DEV_ROUTES, PLATFORM_ROUTES } from "./routes.jsx";

/** Route tree: public login, the MFA step, then the verified-session shell. */
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
        <Route
          path="/mfa"
          element={
            <MfaOnly>
              <MfaPage />
            </MfaOnly>
          }
        />
        <Route element={<RequirePlatformAuth />}>
          <Route element={<AppLayout />}>
            <Route index element={<LandingRedirect />} />
            {/* Own account: any verified platform session, no permission. */}
            <Route path="account" element={<AccountPage />} />
            <Route path="account/settings" element={<SettingsPage />} />
            {PLATFORM_ROUTES.map((r) => (
              <Route
                key={r.path}
                path={r.path}
                element={
                  <RequirePlatformPermission permission={r.permission}>
                    {r.element}
                  </RequirePlatformPermission>
                }
              />
            ))}
            {DEV_ROUTES.map((r) => (
              <Route key={r.path} path={r.path} element={r.element} />
            ))}
            <Route path="*" element={<NotFoundState />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
