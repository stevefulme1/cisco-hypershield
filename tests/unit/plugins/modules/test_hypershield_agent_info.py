# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_agent_info"
)


@pytest.fixture
def module_mock():
    with patch(MODULE_PATH + ".AnsibleModule") as mod_cls:
        module = MagicMock()
        module.check_mode = True
        module.params = {
            "api_url": "https://hs.example.com",
            "api_key": "key",
            "validate_certs": True,
            "timeout": 30,
            "agent_id": None,
            "name": None,
            "host": None,
            "status": None,
            "group_id": None,
            "label_selector": None,
            "include_health": False,
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldAgentInfo:
    def test_get_single_agent(self, module_mock, api_mock):
        """Querying by agent_id returns a single agent."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_info

        module_mock.params["agent_id"] = "agent-1"
        api_mock.get.return_value = {"id": "agent-1", "name": "web-agent"}
        hypershield_agent_info.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False
        assert call_kwargs["count"] == 1

    def test_list_agents(self, module_mock, api_mock):
        """Listing all agents returns the full collection."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_info

        api_mock.list_paginated.return_value = [
            {"id": "a1", "name": "agent-1"},
            {"id": "a2", "name": "agent-2"},
        ]
        hypershield_agent_info.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False
        assert call_kwargs["count"] == 2

    def test_filter_by_status(self, module_mock, api_mock):
        """Filtering by status passes the parameter to the API."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_info

        module_mock.params["status"] = "running"
        api_mock.list_paginated.return_value = [{"id": "a1", "status": "running"}]
        hypershield_agent_info.main()

        call_args = api_mock.list_paginated.call_args
        assert "running" in str(call_args)

    def test_include_health(self, module_mock, api_mock):
        """include_health fetches health data for single agent."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_info

        module_mock.params["agent_id"] = "agent-1"
        module_mock.params["include_health"] = True
        api_mock.get.side_effect = [
            {"id": "agent-1", "name": "web-agent"},
            {"status": "healthy", "uptime": 3600},
        ]
        hypershield_agent_info.main()

        assert api_mock.get.call_count == 2
