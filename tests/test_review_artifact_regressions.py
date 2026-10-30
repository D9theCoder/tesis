"""Focused saved-artifact and mocked runtime controls for the range review."""
import json
import os
import stat

import pytest

from evaluation.reporter import write_json_report


@pytest.mark.parametrize("mode", [0o600, 0o640])
def test_replacement_is_private_before_any_content_is_written(tmp_path, monkeypatch, mode):
    path = tmp_path / "private.json"
    path.write_text('{}')
    path.chmod(mode)
    original_fdopen = os.fdopen
    observed = []

    def inspect_descriptor(descriptor, *args, **kwargs):
        observed.append((stat.S_IMODE(os.fstat(descriptor).st_mode), os.fstat(descriptor).st_size))
        return original_fdopen(descriptor, *args, **kwargs)

    monkeypatch.setattr(os, 'fdopen', inspect_descriptor)
    previous_umask = os.umask(0o022)
    try:
        write_json_report(path, {'private': 'contents'})
    finally:
        os.umask(previous_umask)
    assert observed == [(mode, 0)]
    assert stat.S_IMODE(path.stat().st_mode) == mode
    assert json.loads(path.read_text()) == {'private': 'contents'}
    assert list(tmp_path.iterdir()) == [path]
