"""
core/file_handler.py — ThreatTrace file discovery and intake.

Accepts a file or directory path, handles .gz compression transparently,
detects .evtx binary files, and returns a list of file descriptor dicts.

Returns:
    list of {"path": str, "size_bytes": int, "extension": str}
"""

from __future__ import annotations

import gzip
import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Dict, Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

# Extensions scanned when a directory is given
DIRECTORY_EXTENSIONS: set[str] = {
    ".log", ".json", ".xml", ".evtx", ".gz", ".txt", ".csv"
}

# Magic bytes identifying a Windows Event Log (EVTX) file
EVTX_MAGIC = b"ElfFile\x00"


def _detect_evtx(path: Path) -> bool:
    """Return True if the file starts with the EVTX magic bytes."""
    try:
        with open(path, "rb") as fh:
            return fh.read(8) == EVTX_MAGIC
    except OSError:
        return False


def _decompress_gz(gz_path: Path) -> Path:
    """
    Decompress a .gz file into a temp location and return the new path.
    The caller is responsible for cleaning up the temp file when done.
    """
    suffix = gz_path.stem  # filename without .gz
    tmp_fd, tmp_path_str = tempfile.mkstemp(
        suffix=f"_{suffix}", prefix="threattrace_"
    )
    tmp_path = Path(tmp_path_str)
    os.close(tmp_fd)
    with gzip.open(gz_path, "rb") as f_in, open(tmp_path, "wb") as f_out:
        shutil.copyfileobj(f_in, f_out)
    return tmp_path


def _build_descriptor(path: Path, original_extension: str | None = None) -> Dict[str, Any]:
    """Build a file descriptor dict for the given resolved path."""
    ext = original_extension if original_extension else path.suffix.lower()
    return {
        "path": str(path),
        "size_bytes": path.stat().st_size,
        "extension": ext,
    }


def _process_single_file(path: Path) -> Dict[str, Any]:
    """
    Process one file path.

    .gz files are decompressed to a temp path.
    .evtx files are passed through as-is (raw bytes).
    All other files are returned as-is.
    """
    ext = path.suffix.lower()

    if ext == ".gz":
        console.print(f"  [dim]Decompressing[/dim] [cyan]{path.name}[/cyan]…")
        decompressed = _decompress_gz(path)
        inner_ext = decompressed.suffix.lower() or ".log"
        return _build_descriptor(decompressed, original_extension=inner_ext)

    if ext == ".evtx" or _detect_evtx(path):
        return _build_descriptor(path, original_extension=".evtx")

    return _build_descriptor(path)


def load_files(
    path: str,
    recursive: bool = False,
) -> List[Dict[str, Any]]:
    """
    Main entry point.

    Parameters
    ----------
    path:
        A file path or directory path (string).
    recursive:
        If *path* is a directory, recurse into sub-directories.

    Returns
    -------
    list of {"path": str, "size_bytes": int, "extension": str}

    Raises
    ------
    FileNotFoundError
        If *path* does not exist on disk.
    """
    target = Path(path)

    if not target.exists():
        raise FileNotFoundError(
            f"[ThreatTrace] Path not found: '{path}'. "
            "Check that the file or directory exists and is accessible."
        )

    # ------------------------------------------------------------------ file
    if target.is_file():
        descriptor = _process_single_file(target)
        console.print(
            f"[bold cyan]ThreatTrace ›[/bold cyan] Loaded file "
            f"[green]{target.name}[/green] "
            f"([dim]{_fmt_bytes(descriptor['size_bytes'])}[/dim])"
        )
        return [descriptor]

    # ------------------------------------------------------------- directory
    if target.is_dir():
        return _load_directory(target, recursive=recursive)

    raise FileNotFoundError(
        f"[ThreatTrace] '{path}' is neither a file nor a directory."
    )


def _load_directory(directory: Path, recursive: bool) -> List[Dict[str, Any]]:
    """
    Glob a directory for supported log file extensions.
    Shows a Rich progress spinner while scanning.
    """
    pattern = "**/*" if recursive else "*"
    candidates: list[Path] = []

    console.print(
        f"\n[bold cyan]ThreatTrace ›[/bold cyan] Scanning directory "
        f"[green]{directory}[/green]"
        + (" [dim](recursive)[/dim]" if recursive else "")
    )

    # Collect candidate files first (fast pass — no decompression yet)
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("Scanning for log files…", total=None)
        for entry in directory.glob(pattern):
            if entry.is_file() and entry.suffix.lower() in DIRECTORY_EXTENSIONS:
                candidates.append(entry)
        progress.update(task, description=f"Found {len(candidates)} candidate file(s)")

    if not candidates:
        console.print(
            f"[yellow]  No supported log files found in '{directory}'.[/yellow]"
        )
        return []

    # Process (decompress .gz, validate .evtx, etc.) with progress bar
    results: List[Dict[str, Any]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Processing files…", total=len(candidates)
        )
        for fp in sorted(candidates):
            progress.update(task, description=f"[cyan]Processing[/cyan] {fp.name}")
            try:
                descriptor = _process_single_file(fp)
                results.append(descriptor)
            except Exception as exc:  # noqa: BLE001
                console.print(
                    f"  [yellow]Warning:[/yellow] Could not process "
                    f"[dim]{fp}[/dim]: {exc}"
                )
            finally:
                progress.advance(task)

    total_size = sum(d["size_bytes"] for d in results)
    console.print(
        f"[bold cyan]ThreatTrace ›[/bold cyan] "
        f"Loaded [bold]{len(results)}[/bold] file(s) "
        f"([dim]{_fmt_bytes(total_size)} total[/dim])\n"
    )
    return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fmt_bytes(n: int) -> str:
    """Human-readable byte count."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
