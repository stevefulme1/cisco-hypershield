# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_agent_upgrade"
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
            "target_version": "2.0.0",
            "force": False,
            "wait": True,
            "wait_timeout": 300,
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldAgentUpgrade:
    def test_upgrade_agent(self, module_mock, api_mock):
        """Upgrading an agent to a new version sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_upgrade

        api_mock.get.return_value = {"id": "agent-1", "version": "1.0.0"}
        api_mock.post.return_value = {"id": "agent-1", "version": "2.0.0", "status": "upgrading"}
        hypershield_agent_upgrade.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_already_at_target_version(self, module_mock, api_mock):
        """Agent already at target version yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_upgrade

        api_mock.get.return_value = {"id": "agent-1", "version": "2.0.0"}
        hypershield_agent_upgrade.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_check_mode_upgrade(self, module_mock, api_mock):
        """Check mode reports changed but does not call API."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_upgrade

        module_mock.check_mode = True
        api_mock.get.return_value = {"id": "agent-1", "version": "1.0.0"}
        hypershield_agent_upgrade.main()

        api_mock.post.assert_not_called()
        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_force_upgrade(self, module_mock, api_mock):
        """Force upgrade proceeds even at same version."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_upgrade

        module_mock.params["force"] = True
        api_mock.get.return_value = {"id": "agent-1", "version": "2.0.0"}
        api_mock.post.return_value = {"id": "agent-1", "version": "2.0.0", "status": "upgrading"}
        hypershield_agent_upgrade.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True
