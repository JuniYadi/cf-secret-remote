import { render } from "preact";
// Fonts are self-hosted from the npm packages and bundled by Vite. No third-party font CDN (ADR 24).
import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-500.css";
import "@fontsource/inter/latin-600.css";
import "@fontsource/space-grotesk/latin-500.css";
import "@fontsource/space-grotesk/latin-700.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import { App } from "./app.tsx";
import "./styles.css";

const root = document.getElementById("app");
if (!root) throw new Error("cfs: the #app element is missing from index.html");
render(<App />, root);
