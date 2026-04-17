"""
progress.py — Dynamic terminal progress indicator.

Usage:
    with Progress("Parsing symbol table") as p:
        do_slow_work()
        p.update("Writing cache")   # Optional: mid-operation status update

Output (to stderr, refreshed in real time):
    Parsing symbol table ... 3.2s
    Writing cache        ... 3.5s  Done
"""

from __future__ import annotations

import sys
import time
import threading


class Progress:
    """
    Context manager that displays a real-time elapsed-time spinner in a background thread.
    Automatically prints final timing when the with-block exits.
    """

    def __init__(self, message: str, stream=None):
        self._message = message
        self._stream = stream or sys.stderr
        self._start = 0.0
        self._stop_event = threading.Event()
        self._thread = None
        self._final_message = None

    def update(self, message: str):
        """Update the displayed message midway through an operation (does not reset timer)."""
        self._message = message

    def __enter__(self):
        self._start = time.time()
        self._is_tty = hasattr(self._stream, "isatty") and self._stream.isatty()
        self._stop_event.clear()
        if self._is_tty:
            # TTY mode: background thread refreshes the same line in real time
            self._thread = threading.Thread(target=self._run_tty, daemon=True)
            self._thread.start()
        else:
            # Non-TTY (pipe / redirect): just print a start line
            self._stream.write(f"[elf-inspector] {self._message} ...\n")
            self._stream.flush()
        return self

    def __exit__(self, *_):
        elapsed = time.time() - self._start
        if self._is_tty:
            self._stop_event.set()
            if self._thread:
                self._thread.join()
            self._stream.write(f"\r{self._message} ... {elapsed:.1f}s  Done\n")
        else:
            self._stream.write(f"[elf-inspector] {self._message} ... Done ({elapsed:.1f}s)\n")
        self._stream.flush()

    def _run_tty(self):
        """TTY mode: background thread continuously updates the same line."""
        spinner = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        try:
            "⠋".encode(self._stream.encoding or "utf-8")
        except (UnicodeEncodeError, LookupError):
            spinner = ["|", "/", "-", "\\"]

        idx = 0
        while not self._stop_event.is_set():
            elapsed = time.time() - self._start
            spin = spinner[idx % len(spinner)]
            self._stream.write(f"\r{self._message} {spin} {elapsed:.1f}s")
            self._stream.flush()
            idx += 1
            self._stop_event.wait(0.1)
