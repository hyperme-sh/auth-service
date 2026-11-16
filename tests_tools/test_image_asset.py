from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

def test_public_asset_exception_requires_bytes_path_coordinate_and_symbol(tmp_path):
    import hashlib
    from classify_base_fingerprint import known_asset
    path=tmp_path/'4/opt/storage/share/jupyter/map'
    path.parent.mkdir(parents=True);path.write_bytes(b'public function symbol')
    asset={'path':'opt/storage/share/jupyter/map','rule':'generic-api-key','start':6,'end':6,
           'symbols':['PublicFunction'], 'member_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
    row={'File':str(path),'RuleID':'generic-api-key','StartLine':6,'EndLine':6,'Secret':'PublicFunction'}
    assert known_asset(row,tmp_path,[asset])
    for key,value in [('Secret','credential'),('StartLine',7),('File',str(tmp_path/'elsewhere'))]:
        assert not known_asset(dict(row,**{key:value}),tmp_path,[asset])
    path.write_bytes(b'changed');assert not known_asset(row,tmp_path,[asset])
