# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_zone_policy"
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
            "name": "dmz-policy",
            "state": "present",
            "source_zone": "dmz",
            "destination_zone": "internal",
            "protocol": "tcp",
            "ports": [443, 8443],
            "action": "allow",
            "log_enabled": True,
            "description": "DMZ to internal HTTPS",
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldZonePolicy:
    def test_create_zone_policy(self, module_mock, api_mock):
        """Creating a new zone policy sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_zone_policy

        api_mock.get.return_value = {"items": []}
        api_mock.post.return_value = {"id": "zp-1", "name": "dmz-policy"}
        hypershield_zone_policy.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_zone_policy_no_change(self, module_mock, api_mock):
        """Existing matching zone policy yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_zone_policy

        existing = {
            "id": "zp-1", "name": "dmz-policy",
            "source_zone": "dmz", "destination_zone": "internal",
            "protocol": "tcp", "ports": [443, 8443],
            "action": "allow", "log_enabled": True,
            "description": "DMZ to internal HTTPS",
        }
        api_mock.get.return_value = {"items": [existing]}
        hypershield_zone_policy.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_delete_zone_policy(self, module_mock, api_mock):
        """Deleting a zone policy calls DELETE and sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_zone_policy

        module_mock.params["state"] = "absent"
        existing = {"id": "zp-1", "name": "dmz-policy"}
        api_mock.get.return_value = {"items": [existing]}
        hypershield_zone_policy.main()

        api_mock.delete.assert_called_once()

    def test_update_zone_policy(self, module_mock, api_mock):
        """Changing ports triggers an update."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_zone_policy

        existing = {
            "id": "zp-1", "name": "dmz-policy",
            "source_zone": "dmz", "destination_zone": "internal",
            "protocol": "tcp", "ports": [443],
            "action": "allow", "log_enabled": True,
            "description": "DMZ to internal HTTPS",
        }
        api_mock.get.return_value = {"items": [existing]}
        api_mock.put.return_value = {"id": "zp-1", "ports": [443, 8443]}
        hypershield_zone_policy.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True
