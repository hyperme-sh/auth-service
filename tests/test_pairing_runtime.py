"""Explicit relay enablement and configured scope bounds."""
import json
import pytest
from auth_service.pairing_runtime import read_scopes
from test_pairing_state import SCOPE


def test_default_disabled_and_bounded_explicit_scopes(monkeypatch,tmp_path):
    monkeypatch.delenv('AUTH_SEA_PAIRING_SCOPES_FILE',raising=False)
    assert read_scopes()==()
    path=tmp_path/'scopes.json';monkeypatch.setenv('AUTH_SEA_PAIRING_SCOPES_FILE',str(path))
    path.write_text(json.dumps({'version':1,'scopes':[SCOPE]}))
    assert read_scopes()==(SCOPE,)
    for rows in ([],[SCOPE,SCOPE],[{**SCOPE,'sourceOrigin':'http://unsafe.example'}]):
        path.write_text(json.dumps({'version':1,'scopes':rows}))
        with pytest.raises(ValueError,match='^Invalid pairing scope configuration$'):read_scopes()
    path.write_text('x'*32769)
    with pytest.raises(ValueError):read_scopes()
