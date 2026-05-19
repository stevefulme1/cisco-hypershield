# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_network_rule"
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
            "name": "block-ssh-external",
            "state": "present",
            "source_cidr": "0.0.0.0/0",
            "destination_cidr": "10.0.0.0/8",
            "protocol": "tcp",
            "port": 22,
            "action": "deny",
            "direction": "inbound",
            "priority": 50,
            "description": "Block external SSH",
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldNetworkRule:
    def test_create_rule(self, module_mock, api_mock):
        """Creating a new network rule sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_network_rule

        api_mock.get.return_value = {"items": []}
        api_mock.post.return_value = {"id": "nr-1", "name": "block-ssh-external"}
        hypershield_network_rule.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_rule_exists_no_change(self, module_mock, api_mock):
        """Existing matching rule yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_network_rule

        existing = {
            "id": "nr-1", "name": "block-ssh-external",
            "source_cidr": "0.0.0.0/0", "destination_cidr": "10.0.0.0/8",
            "protocol": "tcp", "port": 22, "action": "deny",
            "direction": "inbound", "priority": 50,
            "description": "Block external SSH",
        }
        api_mock.get.return_value = {"items": [existing]}
        hypershield_network_rule.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_delete_rule(self, module_mock, api_mock):
        """Deleting a rule calls DELETE."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_network_rule

        module_mock.params["state"] = "absent"
        existing = {"id": "nr-1", "name": "block-ssh-external"}
        api_mock.get.return_value = {"items": [existing]}
        hypershield_network_rule.main()

        api_mock.delete.assert_called_once()

    def test_update_rule(self, module_mock, api_mock):
        """Changing action triggers an update."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_network_rule

        existing = {
            "id": "nr-1", "name": "block-ssh-external",
            "source_cidr": "0.0.0.0/0", "destination_cidr": "10.0.0.0/8",
            "protocol": "tcp", "port": 22, "action": "allow",
            "direction": "inbound", "priority": 50,
            "description": "Block external SSH",
        }
        api_mock.get.return_value = {"items": [existing]}
        api_mock.put.return_value = {"id": "nr-1", "action": "deny"}
        hypershield_network_rule.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_create(self, module_mock, api_mock):
        """Check mode does not create but reports changed."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_network_rule

        module_mock.check_mode = True
        api_mock.get.return_value = {"items": []}
        hypershield_network_rule.main()

        api_mock.post.assert_not_called()
