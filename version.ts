import { version as packageVersion } from "./package.json";

// Release builds replace this identifier with the same version used in the bundle manifest.
declare const __CFS_VERSION__: string | undefined;
export const VERSION = typeof __CFS_VERSION__ === "undefined" ? packageVersion : __CFS_VERSION__;
