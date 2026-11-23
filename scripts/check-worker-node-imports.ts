// Fail closed for new Node builtins: add a mapping only after checking Cloudflare support.
import { readFileSync } from "node:fs";
import ts from "typescript";
import { wranglerSettings } from "./bundle-worker.ts";

const flags = wranglerSettings(
  readFileSync("apps/api/wrangler.example.jsonc", "utf8"),
).compatibility_flags;
const allowed: Record<string, string[]> = { "node:async_hooks": ["nodejs_als", "nodejs_compat"] };
const files = new Bun.Glob("**/*.{ts,tsx,js,mjs}");
let failed = false;
for (const file of files.scanSync({ cwd: "apps/api/src", absolute: true })) {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
  );
  function visit(node: ts.Node): void {
    let specifier: ts.Expression | undefined;
    if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node))
      specifier = node.moduleSpecifier;
    if (
      ts.isCallExpression(node) &&
      (node.expression.kind === ts.SyntaxKind.ImportKeyword ||
        (ts.isIdentifier(node.expression) && node.expression.text === "require"))
    )
      specifier = node.arguments[0];
    if (specifier && ts.isStringLiteralLike(specifier) && specifier.text.startsWith("node:")) {
      const required = allowed[specifier.text];
      if (!required || !required.some((flag) => flags.includes(flag))) {
        console.error(`${file}: ${specifier.text} has no verified compatibility flag enabled`);
        failed = true;
      }
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
}
if (failed) process.exitCode = 1;
