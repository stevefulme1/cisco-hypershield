# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_agent_group"
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
            "name": "web-servers",
            "state": "present",
            "description": "Web server agents",
            "labels": {"tier": "frontend"},
            "enforcement_mode": "monitor",
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldAgentGroup:
    def test_create_group(self, module_mock, api_mock):
        """Creating a new agent group sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_group

        api_mock.get.return_value = {"items": []}
        api_mock.post.return_value = {"id": "grp-1", "name": "web-servers"}
        hypershield_agent_group.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_group_exists_no_change(self, module_mock, api_mock):
        """Existing group matching desired state yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_group

        existing = {
            "id": "grp-1", "name": "web-servers",
            "description": "Web server agents",
            "labels": {"tier": "frontend"},
            "enforcement_mode": "monitor",
        }
        api_mock.get.return_value = {"items": [existing]}
        hypershield_agent_group.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_delete_group(self, module_mock, api_mock):
        """Deleting an existing group calls DELETE."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_group

        module_mock.params["state"] = "absent"
        existing = {"id": "grp-1", "name": "web-servers"}
        api_mock.get.return_value = {"items": [existing]}
        hypershield_agent_group.main()

        api_mock.delete.assert_called_once()
        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_create(self, module_mock, api_mock):
        """Check mode does not create but reports changed."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_agent_group

        module_mock.check_mode = True
        api_mock.get.return_value = {"items": []}
        hypershield_agent_group.main()

        api_mock.post.assert_not_called()
        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True
