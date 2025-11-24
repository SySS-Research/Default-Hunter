"""Non-blocking keyboard input handling for status display."""

import sys
import platform
from contextlib import contextmanager


def check_for_spacebar() -> bool:
    """
    Check if spacebar was pressed without blocking.

    Returns:
        True if spacebar was pressed, False otherwise.
    """
    if not sys.stdin.isatty():
        # Not running in interactive terminal
        return False

    system = platform.system()

    if system == "Windows":
        return _check_spacebar_windows()
    else:
        return _check_spacebar_unix()


def _check_spacebar_windows() -> bool:
    """Windows implementation using msvcrt."""
    try:
        import msvcrt

        if msvcrt.kbhit():
            key = msvcrt.getch()
            # Check for space (0x20) or 's' key
            return key in (b" ", b"s", b"S")
        return False
    except ImportError:
        # msvcrt not available (shouldn't happen on Windows)
        return False


def _check_spacebar_unix() -> bool:
    """Unix/Linux implementation using select."""
    try:
        import select

        # Check if stdin has data available (timeout = 0 for non-blocking)
        ready, _, _ = select.select([sys.stdin], [], [], 0)
        if ready:
            # Read the character
            key = sys.stdin.read(1)
            # Check for space or 's' key
            return key in (" ", "s", "S")
        return False
    except (ImportError, OSError):
        return False


@contextmanager
def raw_terminal_mode():
    """
    Context manager to set terminal to raw mode for single-key input.

    On Unix systems, disables line buffering and echo.
    On Windows, does nothing (not needed with msvcrt).
    """
    if not sys.stdin.isatty():
        # Not a terminal, nothing to do
        yield
        return

    system = platform.system()

    if system == "Windows":
        # Windows doesn't need terminal mode changes with msvcrt
        yield
        return

    # Unix/Linux terminal setup
    try:
        import termios
        import tty

        # Save original terminal settings
        old_settings = termios.tcgetattr(sys.stdin)

        try:
            # Set terminal to cbreak mode (no buffering, no echo, but signals work)
            # This allows Ctrl+C to work unlike raw mode
            tty.setcbreak(sys.stdin.fileno())
            yield
        finally:
            # Always restore original settings
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

    except (ImportError, OSError, termios.error):
        # termios not available or not a TTY, just yield without changes
        yield
