import { AppRouter } from "./app/router.jsx";
import { Providers } from "./app/providers.jsx";

/** Application root: providers (query client, tooltips, toasts, theme) around the router. */
export function App() {
  return (
    <Providers>
      <AppRouter />
    </Providers>
  );
}
