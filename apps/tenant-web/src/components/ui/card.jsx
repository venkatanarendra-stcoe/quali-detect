import { cn } from "@/lib/cn.js";

function Card({ className, ...props }) {
  return (
    <div
      data-slot="card"
      className={cn("rounded-md border border-border bg-card text-card-foreground", className)}
      {...props}
    />
  );
}
function CardHeader({ className, ...props }) {
  return (
    <div
      data-slot="card-header"
      className={cn("flex flex-col gap-1 p-4 pb-2", className)}
      {...props}
    />
  );
}
// Content is supplied by the caller through props (children).
/* eslint-disable jsx-a11y/heading-has-content */
function CardTitle({ className, ...props }) {
  return (
    <h2
      data-slot="card-title"
      className={cn("text-base leading-6 font-semibold", className)}
      {...props}
    />
  );
}
/* eslint-enable jsx-a11y/heading-has-content */
function CardDescription({ className, ...props }) {
  return (
    <p
      data-slot="card-description"
      className={cn("text-sm text-muted-foreground", className)}
      {...props}
    />
  );
}
function CardContent({ className, ...props }) {
  return <div data-slot="card-content" className={cn("p-4 pt-2", className)} {...props} />;
}

export { Card, CardContent, CardDescription, CardHeader, CardTitle };
