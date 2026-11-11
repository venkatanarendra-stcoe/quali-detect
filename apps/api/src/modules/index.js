import { groupsModule } from "./groups/index.js";
import { identityModule } from "./identity/index.js";
import { platformIdentityModule } from "./platform-identity/index.js";
import { platformTenantsModule } from "./platform-tenants/index.js";
import { roleAssignmentsModule } from "./role-assignments/index.js";
import { rolesModule } from "./roles/index.js";
import { systemModule } from "./system/index.js";
import { usersModule } from "./users/index.js";
// import { workspaceMembersModule } from "./workspace-members/index.js";
import { workspacesModule } from "./workspaces/index.js";

/** Modules registered by the application, in registration order. Add new domain modules here. */
export const modules = [
  systemModule,
  identityModule,
  platformIdentityModule,
  platformTenantsModule,
  usersModule,
  groupsModule,
  rolesModule,
  roleAssignmentsModule,
  workspacesModule,
  // workspaceMembersModule,
];
