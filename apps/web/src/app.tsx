import type { ComponentChildren } from "preact";
import { useEffect } from "preact/hooks";
import { useLocation } from "wouter-preact";
import { Shell } from "./components/Shell.tsx";
import { useKeyStatus, useLang, useSession } from "./lib/hooks.ts";
import { watchActivity } from "./lib/keystore.ts";
import { loadSession } from "./lib/session.ts";
import { guardTarget, type MatchedPage, matchPage, type PageId, SHELL_PAGES } from "./routes.ts";
import { AccessDeniedPage } from "./screens/AccessDenied.tsx";
import { ActivityPage } from "./screens/Activity.tsx";
import { AgentRulesPage } from "./screens/AgentRules.tsx";
import { AlertsPage } from "./screens/Alerts.tsx";
import { CliAuthorizePage } from "./screens/CliAuthorize.tsx";
import { CliDonePage } from "./screens/CliDone.tsx";
import { DevicesPage } from "./screens/Devices.tsx";
import {
  ComingSoonPage,
  LoadErrorPage,
  LoadingPage,
  NotFoundPage,
} from "./screens/Placeholders.tsx";
import { RequestsPage } from "./screens/Requests.tsx";
import { SessionEndedPage } from "./screens/SessionEnded.tsx";
import { SetupPage } from "./screens/Setup.tsx";
import { SetupRecoveryPage } from "./screens/SetupRecovery.tsx";
import { SignInPage } from "./screens/SignIn.tsx";
import { UnlockPage } from "./screens/Unlock.tsx";

/** Pages that render without a session check. */
const PUBLIC_PAGES: ReadonlySet<PageId> = new Set<PageId>([
  "signIn",
  "sessionEnded",
  "forgot",
  "recover",
  "notFound",
]);

export function App() {
  useLang();
  useEffect(() => {
    void loadSession();
    // Any activity in the page resets the idle auto-lock timer (ADR 24).
    return watchActivity(document);
  }, []);
  return <Gate />;
}

/** Chooses the page for the current location, redirecting when the guard says so. */
function Gate() {
  const [location, navigate] = useLocation();
  const session = useSession();
  const keys = useKeyStatus();
  const page = matchPage(location);
  const target = guardTarget({
    page: page.id,
    phase: session.phase,
    vaultReady: session.me?.vaultReady ?? false,
    unlocked: keys.unlocked,
  });

  useEffect(() => {
    if (target !== null && target !== location) navigate(target, { replace: true });
  }, [target, location, navigate]);

  if (target !== null) return <LoadingPage />;
  return renderPage(page, session.phase);
}

function renderPage(
  page: MatchedPage,
  phase: "loading" | "signed-out" | "error" | "ready",
): ComponentChildren {
  switch (page.id) {
    case "signIn":
      return <SignInPage />;
    case "sessionEnded":
      return <SessionEndedPage />;
    case "forgot":
    case "recover":
      return <ComingSoonPage id={page.id} shell={false} />;
    case "notFound":
      return <NotFoundPage />;
    default:
      break;
  }
  if (phase === "loading") return <LoadingPage />;
  if (phase === "error") return <LoadErrorPage onRetry={() => void loadSession()} />;
  if (phase !== "ready") return <LoadingPage />;

  switch (page.id) {
    case "setup":
      return <SetupPage />;
    case "setupRecovery":
      return <SetupRecoveryPage />;
    case "unlock":
      return <UnlockPage />;
    case "cliAuthorize":
      return <CliAuthorizePage />;
    case "cliDone":
      return <CliDonePage />;
    case "denied":
      return (
        <ShellFrame>
          <AccessDeniedPage name={page.name ?? ""} />
        </ShellFrame>
      );
    case "activity":
      return (
        <ShellFrame>
          <ActivityPage />
        </ShellFrame>
      );
    case "alerts":
      return (
        <ShellFrame>
          <AlertsPage />
        </ShellFrame>
      );
    case "requests":
      return (
        <ShellFrame>
          <RequestsPage />
        </ShellFrame>
      );
    case "agentRules":
      return (
        <ShellFrame>
          <AgentRulesPage />
        </ShellFrame>
      );
    case "devices":
      return (
        <ShellFrame>
          <DevicesPage />
        </ShellFrame>
      );
    default:
      if (SHELL_PAGES.has(page.id)) {
        return (
          <ShellFrame>
            <ComingSoonPage id={page.id} shell={true} />
          </ShellFrame>
        );
      }
      return <NotFoundPage />;
  }
}

/** Shell pages render only when the vault is unlocked. The guard redirects first, so this is a fallback. */
function ShellFrame({ children }: { children: ComponentChildren }) {
  const keys = useKeyStatus();
  const session = useSession();
  if (!keys.unlocked || !session.me) return <LoadingPage />;
  return <Shell>{children}</Shell>;
}
