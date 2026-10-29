import pytest

from onlymessh.cli import main


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "onlymessh" in capsys.readouterr().out


def test_missing_domain_is_an_error(capsys):
    with pytest.raises(SystemExit):
        main([])
