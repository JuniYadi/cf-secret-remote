// Maps the secrets pages from routes.ts to their screens. app.tsx calls this for shell pages, so the secrets
// screens stay out of its switch. Returns null for every other page.

import type { ComponentChildren } from "preact";
import "../styles/secrets.css";
import type { MatchedPage } from "../routes.ts";
import { SecretDetailPage } from "./SecretDetail.tsx";
import { SecretEditPage } from "./SecretEdit.tsx";
import { SecretHistoryPage } from "./SecretHistory.tsx";
import { SecretImportPage } from "./SecretImport.tsx";
import { SecretImportReviewPage } from "./SecretImportReview.tsx";
import { SecretNewPage } from "./SecretNew.tsx";
import { SecretsListPage } from "./SecretsList.tsx";
import { SecretVersionsPage } from "./SecretVersions.tsx";

export function renderSecretPage(page: MatchedPage): ComponentChildren | null {
  const name = page.name ?? "";
  switch (page.id) {
    case "secrets":
      return <SecretsListPage />;
    case "secretsNew":
      return <SecretNewPage />;
    case "secretsImport":
      return <SecretImportPage />;
    case "secretsImportReview":
      return <SecretImportReviewPage />;
    case "secretDetail":
      return <SecretDetailPage name={name} />;
    case "secretEdit":
      return <SecretEditPage name={name} />;
    case "secretVersions":
      return <SecretVersionsPage name={name} />;
    case "secretHistory":
      return <SecretHistoryPage name={name} />;
    default:
      return null;
  }
}
