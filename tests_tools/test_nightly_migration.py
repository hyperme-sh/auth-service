from pathlib import Path

def test_ci_ddl_matches_owner_migration():
    root=Path(__file__).parents[1]
    assert (root/'src/auth_service/migrations/0006_nightly_run.sql').read_bytes()==(root/'tests/fixtures/nightly/0006_nightly_run.sql').read_bytes()
