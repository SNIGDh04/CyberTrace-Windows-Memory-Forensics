import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = Path(os.getenv("CYBERTRACE_DATA_DIR", PROJECT_ROOT / "data")).expanduser().resolve()
RAW_DIR = DATA_DIR / "raw"
VOLATILITY_OUTPUT_DIR = DATA_DIR / "volatility_output"
DATABASE_PATH = DATA_DIR / "cybertrace.sqlite3"
FRONTEND_DIR = PROJECT_ROOT / "frontend"
STORAGE_DIR = DATA_DIR / "storage"
TEMP_UPLOAD_DIR = DATA_DIR / "tmp_uploads"

# Upload limits (GiB)
DEFAULT_UPLOAD_LIMIT_GIB = int(os.getenv("CYBERTRACE_DEFAULT_UPLOAD_LIMIT_GIB", "16"))
MAX_ADMIN_UPLOAD_LIMIT_GIB = int(os.getenv("CYBERTRACE_MAX_ADMIN_UPLOAD_LIMIT_GIB", "64"))
UPLOAD_CHUNK_SIZE_BYTES = int(os.getenv("CYBERTRACE_UPLOAD_CHUNK_SIZE_BYTES", str(4 * 1024 * 1024)))

# Backward-compatible absolute byte limit used by legacy single-shot upload
MAX_UPLOAD_BYTES = int(
    os.getenv(
        "CYBERTRACE_MAX_UPLOAD_BYTES",
        str(DEFAULT_UPLOAD_LIMIT_GIB * 1024**3),
    )
)

PLUGIN_TIMEOUT_SECONDS = int(os.getenv("CYBERTRACE_PLUGIN_TIMEOUT_SECONDS", "3600"))
VOLATILITY_BINARY = os.getenv("CYBERTRACE_VOLATILITY_BINARY", "vol")

# Comma-separated list of approved absolute roots for mounted forensic imports
_default_mounts = str(DATA_DIR / "mounted")
_raw_mounts = os.getenv("CYBERTRACE_ALLOWED_MOUNT_ROOTS", _default_mounts)
ALLOWED_MOUNT_ROOTS: list[Path] = []
for part in _raw_mounts.split(","):
    part = part.strip()
    if part:
        try:
            ALLOWED_MOUNT_ROOTS.append(Path(part).expanduser().resolve())
        except Exception:
            pass
if not ALLOWED_MOUNT_ROOTS:
    ALLOWED_MOUNT_ROOTS = [Path(_default_mounts).resolve()]

SUPPORTED_PLUGINS = (
    "windows.info",
    "windows.pslist",
    "windows.pstree",
    "windows.cmdline",
    "windows.netscan",
    "windows.dlllist",
    "windows.malfind",
)


def ensure_data_directories() -> None:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    VOLATILITY_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    TEMP_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    for root in ALLOWED_MOUNT_ROOTS:
        try:
            root.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass


def effective_upload_limit_bytes(investigator_limit_gib: int | None = None) -> int:
    """Resolve the effective byte limit: min(investigator, admin max, free disk)."""
    inv = investigator_limit_gib if investigator_limit_gib is not None else DEFAULT_UPLOAD_LIMIT_GIB
    inv = max(1, min(inv, MAX_ADMIN_UPLOAD_LIMIT_GIB))
    limit = inv * 1024**3
    try:
        import shutil

        free = shutil.disk_usage(str(STORAGE_DIR if STORAGE_DIR.exists() else DATA_DIR)).free
        free_usable = max(0, free - 256 * 1024**2)
        limit = min(limit, free_usable)
    except OSError:
        pass
    return int(limit)
