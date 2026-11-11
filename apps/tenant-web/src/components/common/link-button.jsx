import { Link } from "react-router";
import { Button } from "@/components/ui/button.jsx";

/**
 * A button that navigates. When `disabled` it renders a real disabled <button>: the `disabled` attribute does nothing on an
 * anchor, so a link styled as a button would stay clickable (this is what permission gates clone into when they disable).
 * @param {{ to: string, disabled?: boolean, children: any } & import("react").ComponentProps<typeof Button>} props
 */
export function LinkButton({ to, disabled = false, children, ...props }) {
  if (disabled)
    return (
      <Button disabled {...props}>
        {children}
      </Button>
    );
  return (
    <Button asChild {...props}>
      <Link to={to}>{children}</Link>
    </Button>
  );
}
