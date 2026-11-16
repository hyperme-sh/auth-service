from pathlib import Path

def test_private_proof_ddl_matches_ci_contract():
    root=Path(__file__).resolve().parents[1]
    assert (root/'src/auth_service/migrations/0007_linked_oidc.sql').read_bytes()==(root/'tests/fixtures/linked-oidc/0007_linked_oidc.sql').read_bytes()
