import { Toaster as Sonner } from "sonner";

/** Toast host. Colors come from the tokens so it follows the light/dark theme. @param {{ theme: "light" | "dark" }} props */
function Toaster({ theme }) {
  return (
    <Sonner
      theme={theme}
      position="bottom-right"
      toastOptions={{
        style: {
          background: "var(--popover)",
          color: "var(--popover-foreground)",
          border: "1px solid var(--border)",
        },
      }}
    />
  );
}

export { Toaster };
