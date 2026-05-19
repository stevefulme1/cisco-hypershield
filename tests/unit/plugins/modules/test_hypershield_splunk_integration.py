# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_splunk_integration"
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
            "splunk_url": "https://splunk.example.com:8088",
            "hec_token": "splunk-hec-token",
            "index": "hypershield",
            "source_type": "hypershield:events",
            "verify_ssl": True,
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldSplunkIntegration:
    def test_create_integration(self, module_mock, api_mock):
        """Creating Splunk integration sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_splunk_integration

        api_mock.get.return_value = {"configured": False}
        api_mock.post.return_value = {"configured": True, "splunk_url": "https://splunk.example.com:8088"}
        hypershield_splunk_integration.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_integration_exists(self, module_mock, api_mock):
        """Existing matching integration yields changed=False."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_splunk_integration

        existing = {
            "configured": True,
            "splunk_url": "https://splunk.example.com:8088",
            "index": "hypershield", "source_type": "hypershield:events",
            "verify_ssl": True,
        }
        api_mock.get.return_value = existing
        hypershield_splunk_integration.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is False

    def test_remove_integration(self, module_mock, api_mock):
        """Removing Splunk integration calls DELETE."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_splunk_integration

        module_mock.params["state"] = "absent"
        api_mock.get.return_value = {"configured": True}
        hypershield_splunk_integration.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode(self, module_mock, api_mock):
        """Check mode does not call API."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_splunk_integration

        module_mock.check_mode = True
        api_mock.get.return_value = {"configured": False}
        hypershield_splunk_integration.main()

        api_mock.post.assert_not_called()
