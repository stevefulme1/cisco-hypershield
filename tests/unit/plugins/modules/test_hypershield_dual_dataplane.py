# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_dual_dataplane"
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
            "agent_id": "agent-1",
            "state": "present",
            "primary_dataplane": "dp-a",
            "secondary_dataplane": "dp-b",
            "failover_mode": "automatic",
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldDualDataplane:
    def test_enable_dual_dataplane(self, module_mock, api_mock):
        """Enabling dual dataplane on an agent sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dual_dataplane

        api_mock.get.return_value = {"agent_id": "agent-1", "dual_dataplane": {"enabled": False}}
        api_mock.post.return_value = {"agent_id": "agent-1", "dual_dataplane": {"enabled": True}}
        hypershield_dual_dataplane.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_already_enabled(self, module_mock, api_mock):
        """Already-enabled dual dataplane yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dual_dataplane

        existing = {
            "agent_id": "agent-1",
            "dual_dataplane": {
                "enabled": True, "primary_dataplane": "dp-a",
                "secondary_dataplane": "dp-b", "failover_mode": "automatic",
            },
        }
        api_mock.get.return_value = existing
        hypershield_dual_dataplane.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_disable_dual_dataplane(self, module_mock, api_mock):
        """Setting state=absent disables dual dataplane."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dual_dataplane

        module_mock.params["state"] = "absent"
        existing = {"agent_id": "agent-1", "dual_dataplane": {"enabled": True}}
        api_mock.get.return_value = existing
        hypershield_dual_dataplane.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode(self, module_mock, api_mock):
        """Check mode does not call API."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dual_dataplane

        module_mock.check_mode = True
        api_mock.get.return_value = {"agent_id": "agent-1", "dual_dataplane": {"enabled": False}}
        hypershield_dual_dataplane.main()

        api_mock.post.assert_not_called()
