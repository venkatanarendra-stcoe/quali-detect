import { Providers } from "./app/providers.jsx";
import { AppRouter } from "./app/router.jsx";

/** Root Console application root: providers (query client, tooltips, toasts, theme) around the router. */
export function App() {
  return (
    <Providers>
      <AppRouter />
    </Providers>
  );
}
