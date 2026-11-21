/** A command receives its arguments (the command word already removed) and the --host flag, if any. */
export type Handler = (args: string[], hostFlag?: string) => Promise<void> | void;
export type Commands = Record<string, { run: Handler; help: string }>;
