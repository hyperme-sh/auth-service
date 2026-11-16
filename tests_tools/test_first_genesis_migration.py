from pathlib import Path

def test_first_genesis_fixture_matches_image_migration():
    root=Path(__file__).resolve().parents[1]
    assert (root/'tests/fixtures/first-genesis/0009_first_genesis.sql').read_bytes()==(root/'src/auth_service/migrations/0009_first_genesis.sql').read_bytes()
