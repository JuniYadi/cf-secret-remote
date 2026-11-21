import { runVectorChecks } from "./checks.ts";

// Bundled by build.ts into an IIFE. The Playwright spec calls the function on the page.
(globalThis as unknown as { runVectorChecks: typeof runVectorChecks }).runVectorChecks =
  runVectorChecks;
