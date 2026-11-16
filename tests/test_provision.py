import json
import os
import stat

import pytest

from scripts.provision import provision


def test_provision_creates_readable_realm_and_preserves_existing_credentials(tmp_path):
    directory = tmp_path / ".local"
    credentials = provision(directory)
    realm = directory / "securemcp-realm.json"
    definition = json.loads(realm.read_text(encoding="utf-8"))
    assert definition["realm"] == "securemcp"
    assert any(user["username"] == "aurora-security" for user in definition["users"])
    if os.name == "posix":
        realm.chmod(0o600)
        inode = realm.stat().st_ino

    assert provision(directory) == credentials
    if os.name == "posix":
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        assert stat.S_IMODE((directory / "secrets.env").stat().st_mode) == 0o600
        assert stat.S_IMODE(realm.stat().st_mode) == 0o644
        assert realm.stat().st_ino == inode


@pytest.mark.skipif(os.name != "posix", reason="POSIX access modes")
def test_provision_rejects_shared_configuration_directory(tmp_path):
    directory = tmp_path / "shared"
    directory.mkdir()
    directory.chmod(0o755)
    with pytest.raises(ValueError, match="configuration directory private"):
        provision(directory)
    assert not list(directory.iterdir())
