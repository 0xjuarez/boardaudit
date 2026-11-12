"""Board profile tests."""

import pytest

from boardaudit.boards import BOARDS, get_board, list_boards

EXPECTED = {
    "esp32", "esp32-s2", "esp32-s3", "esp32-c3", "esp32-c6",
    "esp32-h2", "esp8266", "stm32f4", "stm32l4", "stm32h7",
    "rp2040", "nrf52840", "atmega328p", "samd21", "teensy41",
}


def test_all_boards_present():
    assert set(BOARDS) == EXPECTED


def test_board_fields():
    for profile in list_boards():
        assert profile.flash_size > 0
        assert profile.app_offset >= 0
        assert profile.default_baud > 0
        assert profile.acquisition_tool


def test_esp32_profile():
    profile = get_board("esp32")
    assert profile.app_offset == 0x10000
    assert profile.flash_size == 4 * 1024 * 1024


def test_unknown_board():
    with pytest.raises(ValueError):
        get_board("not-a-board")


def test_list_sorted():
    ids = [p.board_id for p in list_boards()]
    assert ids == sorted(ids)
