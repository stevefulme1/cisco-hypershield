# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_dpu_config"
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
            "dpu_type": "nvidia-bluefield3",
            "offload_mode": "full",
            "network_interfaces": ["ens1f0"],
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldDpuConfig:
    def test_configure_dpu(self, module_mock, api_mock):
        """Configuring DPU offload on an agent sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dpu_config

        api_mock.get.return_value = None
        api_mock.post.return_value = {"agent_id": "agent-1", "enabled": True}
        hypershield_dpu_config.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_dpu_already_configured(self, module_mock, api_mock):
        """Existing matching DPU config yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dpu_config

        existing = {
            "agent_id": "agent-1", "enabled": True,
            "dpu_type": "nvidia-bluefield3", "offload_mode": "full",
            "network_interfaces": ["ens1f0"],
        }
        api_mock.get.return_value = existing
        hypershield_dpu_config.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_disable_dpu(self, module_mock, api_mock):
        """Setting state=absent disables DPU offload."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dpu_config

        module_mock.params["state"] = "absent"
        existing = {"agent_id": "agent-1", "enabled": True}
        api_mock.get.return_value = existing
        hypershield_dpu_config.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_dpu(self, module_mock, api_mock):
        """Check mode does not call API for DPU configuration."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_dpu_config

        module_mock.check_mode = True
        api_mock.get.return_value = None
        hypershield_dpu_config.main()

        api_mock.post.assert_not_called()
