# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_telemetry"
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
            "state": "present",
            "collection_interval": 60,
            "metrics_enabled": True,
            "flow_logs_enabled": True,
            "export_format": "opentelemetry",
            "export_endpoint": "https://otel.example.com:4317",
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldTelemetry:
    def test_configure_telemetry(self, module_mock, api_mock):
        """Configuring telemetry sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_telemetry

        api_mock.get.return_value = {"enabled": False}
        api_mock.put.return_value = {"enabled": True, "collection_interval": 60}
        hypershield_telemetry.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_telemetry_no_change(self, module_mock, api_mock):
        """Matching telemetry config yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_telemetry

        existing = {
            "enabled": True, "collection_interval": 60,
            "metrics_enabled": True, "flow_logs_enabled": True,
            "export_format": "opentelemetry",
            "export_endpoint": "https://otel.example.com:4317",
        }
        api_mock.get.return_value = existing
        hypershield_telemetry.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_disable_telemetry(self, module_mock, api_mock):
        """Setting state=absent disables telemetry."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_telemetry

        module_mock.params["state"] = "absent"
        api_mock.get.return_value = {"enabled": True}
        hypershield_telemetry.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode(self, module_mock, api_mock):
        """Check mode does not modify telemetry config."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_telemetry

        module_mock.check_mode = True
        api_mock.get.return_value = {"enabled": False}
        hypershield_telemetry.main()

        api_mock.put.assert_not_called()
        api_mock.post.assert_not_called()
