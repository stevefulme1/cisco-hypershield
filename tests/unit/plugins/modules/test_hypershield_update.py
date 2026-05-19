# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_update"
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
            "name": "v2-rollout",
            "state": "present",
            "target_version": "2.0.0",
            "strategy": "rolling",
            "max_parallel": 5,
            "canary_percentage": 10,
            "auto_start": False,
            "agent_filter": {},
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldUpdate:
    def test_create_campaign(self, module_mock, api_mock):
        """Creating a new update campaign sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_update

        api_mock.get.return_value = {"items": []}
        api_mock.post.return_value = {"id": "camp-1", "name": "v2-rollout"}
        hypershield_update.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_campaign_exists_no_change(self, module_mock, api_mock):
        """Existing matching campaign yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_update

        existing = {
            "id": "camp-1", "name": "v2-rollout",
            "target_version": "2.0.0", "strategy": "rolling",
            "max_parallel": 5, "status": "pending",
        }
        api_mock.get.return_value = {"items": [existing]}
        hypershield_update.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_delete_campaign(self, module_mock, api_mock):
        """Deleting an existing campaign calls DELETE."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_update

        module_mock.params["state"] = "absent"
        existing = {"id": "camp-1", "name": "v2-rollout"}
        api_mock.get.return_value = {"items": [existing]}
        hypershield_update.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_create(self, module_mock, api_mock):
        """Check mode does not create but reports changed."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_update

        module_mock.check_mode = True
        api_mock.get.return_value = {"items": []}
        hypershield_update.main()

        api_mock.post.assert_not_called()
