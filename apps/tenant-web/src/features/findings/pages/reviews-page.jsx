import { AppPageLayout } from "@qmentisai/ui";
import { useParams } from "react-router";
import { ReviewQueue } from "../components/review-queue.jsx";

/**
 * T-34 Reviews (nav "Security Reviews"): analysts work through findings that need a decision. The route needs
 * `security_review.view`; deciding needs `finding.review` (the form is replaced by a sentence without it).
 */
export function ReviewsPage() {
  const { workspaceId } = useParams();
  return (
    <AppPageLayout
      title="Reviews"
      description="Findings waiting for a decision. A lead approves every decision before anything changes."
      scroll={false}
    >
      <ReviewQueue workspaceId={workspaceId} />
    </AppPageLayout>
  );
}
