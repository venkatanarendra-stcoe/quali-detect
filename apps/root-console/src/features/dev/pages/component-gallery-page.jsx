import { AppPageLayout } from "@qmentisai/ui";
import { useState } from "react";
import { SupportAccessBanner } from "@/components/common/support-access-banner.jsx";
import { EnvironmentStrip } from "@/components/layout/environment-strip.jsx";
import { Button } from "@/components/ui/button.jsx";
import { resolveEnvironment } from "@/lib/environment.js";

const minutes = (n) => new Date(Date.now() + n * 60_000);

/** Development-only gallery of Root-specific components in each state (`/dev/components`; not registered in production builds). */
export function ComponentGalleryPage() {
  const [ended, setEnded] = useState(false);
  return (
    <AppPageLayout
      title="Component gallery"
      description="Development only. Static examples; no real grants exist yet."
      offset="4.5rem"
    >
      <section aria-labelledby="g-env" className="mb-6 space-y-2">
        <h2 id="g-env" className="text-base font-semibold">
          Environment strip
        </h2>
        {["development", "staging", "production"].map((id) => (
          <div key={id} className="[&>div]:static">
            <EnvironmentStrip env={resolveEnvironment(id)} />
          </div>
        ))}
      </section>
      <section aria-labelledby="g-banner" className="space-y-2">
        <h2 id="g-banner" className="text-base font-semibold">
          Support access banner
        </h2>
        <div className="overflow-hidden rounded-md border border-border">
          <SupportAccessBanner
            tenantName="Acme Corp"
            reason="Investigate failed scan (ticket 4821)"
            expiresAt={minutes(42)}
            onEnd={() => setEnded(true)}
          />
          <SupportAccessBanner
            tenantName="Acme Corp"
            reason="Investigate failed scan (ticket 4821)"
            expiresAt={minutes(6)}
            onEnd={() => setEnded(true)}
          />
          <SupportAccessBanner
            tenantName="Acme Corp"
            reason="Investigate failed scan (ticket 4821)"
            expiresAt={minutes(-1)}
            onEnd={() => setEnded(true)}
          />
        </div>
        {ended ? (
          <p role="status" className="text-sm text-muted-foreground">
            End access clicked (the gallery does not change anything).{" "}
            <Button size="sm" variant="ghost" onClick={() => setEnded(false)}>
              Reset
            </Button>
          </p>
        ) : null}
      </section>
    </AppPageLayout>
  );
}
