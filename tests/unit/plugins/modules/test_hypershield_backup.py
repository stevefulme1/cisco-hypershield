# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_backup"
)


@pytest.fixture
def module_mock():
    with patch(MODULE_PATH + ".AnsibleModule") as mod_cls:
        module = MagicMock()
        module.check_mode = False
        module.params = {
            "api_url": "https://hs.example.com",
            "api_key": "key",
            "validate_certs": True,
            "timeout": 30,
            "state": "present",
            "name": "daily-backup",
            "include_policies": True,
            "include_agents": True,
            "include_config": True,
            "schedule": "daily",
            "retention_days": 30,
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldBackup:
    def test_create_backup(self, module_mock, api_mock):
        """Creating a backup job sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_backup

        api_mock.get.return_value = {"items": []}
        api_mock.post.return_value = {"id": "bak-1", "name": "daily-backup", "status": "pending"}
        hypershield_backup.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_backup_exists_no_change(self, module_mock, api_mock):
        """Existing matching backup config yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_backup

        existing = {
            "id": "bak-1", "name": "daily-backup",
            "include_policies": True, "include_agents": True,
            "include_config": True, "schedule": "daily",
            "retention_days": 30,
        }
        api_mock.get.return_value = {"items": [existing]}
        hypershield_backup.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_delete_backup(self, module_mock, api_mock):
        """Deleting a backup job calls DELETE."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_backup

        module_mock.params["state"] = "absent"
        existing = {"id": "bak-1", "name": "daily-backup"}
        api_mock.get.return_value = {"items": [existing]}
        hypershield_backup.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_create(self, module_mock, api_mock):
        """Check mode does not create backup."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_backup

        module_mock.check_mode = True
        api_mock.get.return_value = {"items": []}
        hypershield_backup.main()

        api_mock.post.assert_not_called()

    def test_update_retention(self, module_mock, api_mock):
        """Changing retention_days triggers an update."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_backup

        existing = {
            "id": "bak-1", "name": "daily-backup",
            "include_policies": True, "include_agents": True,
            "include_config": True, "schedule": "daily",
            "retention_days": 7,
        }
        api_mock.get.return_value = {"items": [existing]}
        api_mock.put.return_value = {"id": "bak-1", "retention_days": 30}
        hypershield_backup.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True
