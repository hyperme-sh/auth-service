from pathlib import Path


def test_installed_wheel_contract_uses_exact_owner_migration():
    root=Path(__file__).resolve().parents[1]
    assert (root/'src/auth_service/migrations/0008_first_oidc_link.sql').read_bytes()==(root/'tests/fixtures/first-oidc/0008_first_oidc_link.sql').read_bytes()
