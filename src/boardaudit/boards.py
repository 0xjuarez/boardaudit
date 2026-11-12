"""Board profiles.

Board profiles are the ``kind == "board"`` entries of the unified
profile catalog in ``profiles.py``. This module keeps the 0.1.0 /
0.2.0 BoardProfile API working: acquisition code imports
``get_board`` and ``list_boards`` from here.
"""

from __future__ import annotations

from dataclasses import dataclass

from .profiles import Profile, list_profiles


@dataclass(frozen=True)
class BoardProfile:
    board_id: str
    name: str
    family: str
    flash_size: int  # bytes
    app_offset: int  # bytes
    default_baud: int
    acquisition_tool: str
    acquisition_optional: bool = True
    notes: str = ""


def _from_profile(profile: Profile) -> BoardProfile:
    return BoardProfile(
        board_id=profile.profile_id,
        name=profile.name,
        family=profile.family,
        flash_size=profile.flash_size,
        app_offset=profile.app_offset,
        default_baud=profile.default_baud,
        acquisition_tool=profile.acquisition_tool,
        notes=profile.notes,
    )


def _board_profiles() -> dict[str, BoardProfile]:
    return {
        p.profile_id: _from_profile(p) for p in list_profiles(kind="board")
    }


# Built-in boards, plus any user board profiles found in the user
# profiles directory or ./profiles/ at import time.
BOARDS: dict[str, BoardProfile] = _board_profiles()


def get_board(board_id: str) -> BoardProfile:
    """Return the profile for board_id, or raise ValueError for unknown ids."""
    if not isinstance(board_id, str):
        raise ValueError("board id must be a string")
    profile = _board_profiles().get(board_id.strip().lower())
    if profile is None:
        known = ", ".join(sorted(_board_profiles()))
        raise ValueError(f"unknown board: {board_id!r}. Known boards: {known}")
    return profile


def list_boards() -> list[BoardProfile]:
    """Return all board profiles sorted by board id."""
    return [BOARDS[key] for key in sorted(BOARDS)]
