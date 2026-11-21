import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const PROJECT_ROOT = path.resolve(__dirname, "..");
export const DATA_DIR = path.resolve(
  process.env.CYBERTRACE_DATA_DIR || path.join(PROJECT_ROOT, "data")
);
export const RAW_DIR = path.join(DATA_DIR, "raw");
export const VOLATILITY_OUTPUT_DIR = path.join(DATA_DIR, "volatility_output");
export const FRONTEND_DIR = path.join(PROJECT_ROOT, "frontend");
export const STORAGE_DIR = path.join(DATA_DIR, "storage");
export const TEMP_UPLOAD_DIR = path.join(DATA_DIR, "tmp_uploads");

export const DEFAULT_UPLOAD_LIMIT_GIB = Number.parseInt(
  process.env.CYBERTRACE_DEFAULT_UPLOAD_LIMIT_GIB || "16",
  10
);
export const MAX_ADMIN_UPLOAD_LIMIT_GIB = Number.parseInt(
  process.env.CYBERTRACE_MAX_ADMIN_UPLOAD_LIMIT_GIB || "64",
  10
);
export const UPLOAD_CHUNK_SIZE_BYTES = Number.parseInt(
  process.env.CYBERTRACE_UPLOAD_CHUNK_SIZE_BYTES || String(4 * 1024 * 1024),
  10
);

const GIB = 1024 ** 3;
export const MAX_UPLOAD_BYTES = Number.parseInt(
  process.env.CYBERTRACE_MAX_UPLOAD_BYTES || String(DEFAULT_UPLOAD_LIMIT_GIB * GIB),
  10
);

export const PLUGIN_TIMEOUT_SECONDS = Number.parseInt(
  process.env.CYBERTRACE_PLUGIN_TIMEOUT_SECONDS || "3600",
  10
);
export const VOLATILITY_BINARY = process.env.CYBERTRACE_VOLATILITY_BINARY || "vol";

const defaultMount = path.join(DATA_DIR, "mounted");
const rawMounts = process.env.CYBERTRACE_ALLOWED_MOUNT_ROOTS || defaultMount;
const parsedMounts: string[] = [];
for (const part of rawMounts.split(",")) {
  const trimmed = part.trim();
  if (trimmed) {
    parsedMounts.push(path.resolve(trimmed));
  }
}
export const ALLOWED_MOUNT_ROOTS: string[] =
  parsedMounts.length > 0 ? parsedMounts : [path.resolve(defaultMount)];

export const SUPPORTED_PLUGINS = [
  "windows.info",
  "windows.pslist",
  "windows.pstree",
  "windows.cmdline",
  "windows.netscan",
  "windows.dlllist",
  "windows.malfind",
] as const;

export type SupportedPlugin = (typeof SUPPORTED_PLUGINS)[number];

export function ensureDataDirectories(): void {
  for (const dir of [RAW_DIR, VOLATILITY_OUTPUT_DIR, STORAGE_DIR, TEMP_UPLOAD_DIR]) {
    fs.mkdirSync(dir, { recursive: true });
  }
  for (const root of ALLOWED_MOUNT_ROOTS) {
    try {
      fs.mkdirSync(root, { recursive: true });
    } catch {
      // Ignore uncreatable external mount roots
    }
  }
}

export function availableDiskBytes(targetPath: string = STORAGE_DIR): number {
  const checkPath = fs.existsSync(targetPath) ? targetPath : DATA_DIR;
  try {
    const stats = fs.statfsSync(checkPath);
    return Number(stats.bavail) * Number(stats.bsize);
  } catch {
    return 0;
  }
}

export function effectiveUploadLimitBytes(investigatorLimitGib?: number | null): number {
  const requested =
    investigatorLimitGib !== undefined && investigatorLimitGib !== null
      ? investigatorLimitGib
      : DEFAULT_UPLOAD_LIMIT_GIB;
  const clamped = Math.max(1, Math.min(requested, MAX_ADMIN_UPLOAD_LIMIT_GIB));
  let limit = clamped * GIB;
  const free = availableDiskBytes(STORAGE_DIR);
  if (free > 0) {
    const freeUsable = Math.max(0, free - 256 * 1024 * 1024);
    limit = Math.min(limit, freeUsable);
  }
  return Math.floor(limit);
}
