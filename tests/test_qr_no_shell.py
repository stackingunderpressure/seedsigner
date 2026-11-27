"""helpers/qr.py: qrencode is called with an argument list, never a shell
string, so QR data can't become a command (outside review, 2026-11-27)."""
import subprocess
from unittest import mock

from seedsigner.helpers.qr import QR


HOSTILE = 'abc"; touch /tmp/seedsigner-pwned; echo "'


def test_qrencode_gets_the_data_as_one_argument_without_a_shell():
    with mock.patch.object(subprocess, "call", return_value=1) as call, \
         mock.patch.object(QR, "qrimage", return_value="fallback"):
        QR().qrimage_io(HOSTILE)
    args, kwargs = call.call_args
    assert not kwargs.get("shell"), "qrencode must not run through a shell"
    cmd = args[0]
    assert isinstance(cmd, list)
    assert cmd[0] == "qrencode"
    assert cmd[-1] == HOSTILE  # the data is one argument, untouched


def test_bad_background_is_not_passed_to_qrencode():
    with mock.patch.object(subprocess, "call", return_value=1) as call, \
         mock.patch.object(QR, "qrimage", return_value="fallback"):
        QR().qrimage_io("x", background_color='808080 -o /etc/passwd')
    cmd = call.call_args[0][0]
    assert isinstance(cmd, list) and "--background=808080" in cmd  # not a colour: the default


def test_missing_qrencode_falls_back_to_the_python_encoder():
    with mock.patch.object(subprocess, "call", side_effect=FileNotFoundError("qrencode")), \
         mock.patch.object(QR, "qrimage", return_value="fallback") as fallback:
        assert QR().qrimage_io("x") == "fallback"
    fallback.assert_called_once()
