# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_microsegmentation_policy"
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
            "name": "db-isolation",
            "state": "present",
            "source_labels": {"app": "web"},
            "destination_labels": {"app": "database"},
            "protocol": "tcp",
            "ports": [5432],
            "action": "allow",
            "priority": 100,
            "description": "Allow web to db",
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldMicrosegmentationPolicy:
    def test_create_policy(self, module_mock, api_mock):
        """Creating a new microsegmentation policy sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_microsegmentation_policy

        api_mock.get.return_value = {"items": []}
        api_mock.post.return_value = {"id": "pol-1", "name": "db-isolation"}
        hypershield_microsegmentation_policy.run_module()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_policy_no_change(self, module_mock, api_mock):
        """Existing matching policy yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_microsegmentation_policy

        existing = {
            "id": "pol-1", "name": "db-isolation",
            "source_labels": {"app": "web"},
            "destination_labels": {"app": "database"},
            "protocol": "tcp", "ports": [5432],
            "action": "allow", "priority": 100,
            "description": "Allow web to db",
        }
        api_mock.get.return_value = {"items": [existing]}
        hypershield_microsegmentation_policy.run_module()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_delete_policy(self, module_mock, api_mock):
        """Deleting an existing policy calls DELETE."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_microsegmentation_policy

        module_mock.params["state"] = "absent"
        existing = {"id": "pol-1", "name": "db-isolation"}
        api_mock.get.return_value = {"items": [existing]}
        hypershield_microsegmentation_policy.run_module()

        api_mock.delete.assert_called_once()

    def test_update_policy(self, module_mock, api_mock):
        """Updating policy ports triggers a PUT."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_microsegmentation_policy

        existing = {
            "id": "pol-1", "name": "db-isolation",
            "source_labels": {"app": "web"},
            "destination_labels": {"app": "database"},
            "protocol": "tcp", "ports": [3306],
            "action": "allow", "priority": 100,
            "description": "Allow web to db",
        }
        api_mock.get.return_value = {"items": [existing]}
        api_mock.put.return_value = {"id": "pol-1", "ports": [5432]}
        hypershield_microsegmentation_policy.run_module()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_create(self, module_mock, api_mock):
        """Check mode does not create but reports changed."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_microsegmentation_policy

        module_mock.check_mode = True
        api_mock.get.return_value = {"items": []}
        hypershield_microsegmentation_policy.run_module()

        api_mock.post.assert_not_called()
