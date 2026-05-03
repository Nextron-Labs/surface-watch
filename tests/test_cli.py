from __future__ import annotations

import pytest

from surface_watch import __version__
from surface_watch.cli import main


def test_main_prints_version(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"surface-watch {__version__}"
