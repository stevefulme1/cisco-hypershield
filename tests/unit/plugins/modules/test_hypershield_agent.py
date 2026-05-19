# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_agent"
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
            "agent_id": None,
            "name": "test-agent",
            "host": "10.0.0.1",
            "state": "present",
            "version": "1.0.0",
            "enforcement_mode": "monitor",
            "labels": {},
            "group_id": None,
            "dpu_offload": False,
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldAgent:
    def test_create_agent(self, module_mock, api_mock):
        """Creating a new agent sets changed=True and posts to API."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent

        api_mock.get.return_value = None
        with patch(MODULE_PATH + ".find_agent", return_value=None):
            api_mock.post.return_value = {"id": "agent-1", "name": "test-agent"}
            hypershield_agent.main()

        module_mock.exit_json.assert_called_once()
        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_agent_already_exists_no_change(self, module_mock, api_mock):
        """Existing agent matching desired state yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent

        existing = {
            "id": "agent-1", "name": "test-agent", "host": "10.0.0.1",
            "version": "1.0.0", "enforcement_mode": "monitor",
            "labels": {}, "group_id": None, "dpu_offload": False,
        }
        with patch(MODULE_PATH + ".find_agent", return_value=existing):
            with patch(MODULE_PATH + ".needs_update", return_value=False):
                hypershield_agent.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_delete_agent(self, module_mock, api_mock):
        """Deleting an existing agent calls DELETE and sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent

        module_mock.params["state"] = "absent"
        module_mock.params["agent_id"] = "agent-1"
        existing = {"id": "agent-1", "name": "test-agent"}
        with patch(MODULE_PATH + ".find_agent", return_value=existing):
            hypershield_agent.main()

        api_mock.delete.assert_called_once_with("/agents/agent-1")
        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_create(self, module_mock, api_mock):
        """Check mode does not call the API but reports changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent

        module_mock.check_mode = True
        with patch(MODULE_PATH + ".find_agent", return_value=None):
            hypershield_agent.main()

        api_mock.post.assert_not_called()
        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_start_agent(self, module_mock, api_mock):
        """Starting a stopped agent posts the start action."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent

        module_mock.params["state"] = "started"
        module_mock.params["agent_id"] = "agent-1"
        existing = {"id": "agent-1", "name": "test-agent", "status": "stopped"}
        with patch(MODULE_PATH + ".find_agent", return_value=existing):
            api_mock.get.return_value = {"id": "agent-1", "status": "running"}
            hypershield_agent.main()

        api_mock.post.assert_called_once_with("/agents/agent-1/start")
