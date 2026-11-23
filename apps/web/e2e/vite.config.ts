import preact from "@preact/preset-vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [preact()],
  server: { proxy: { "/api": process.env.CFS_BROWSER_API } },
});
