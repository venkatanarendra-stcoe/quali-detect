import fp from "fastify-plugin";
import { createEntitlementRepository } from "../entitlements/repository.js";
import { createEntitlementService } from "../entitlements/service.js";

/** Decorates `app.entitlements` = { checkEntitlement, assertEntitlement, assertWithinLimit, consumeQuota, releaseQuota }. */
export default fp(
  async function entitlementsPlugin(app) {
    app.decorate(
      "entitlements",
      createEntitlementService({ repository: createEntitlementRepository({ db: app.infra.db }) }),
    );
  },
  { name: "entitlements", dependencies: ["infrastructure"] },
);
