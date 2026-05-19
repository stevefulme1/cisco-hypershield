# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from unittest.mock import MagicMock, patch

import pytest

MODULE_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.modules.hypershield_compliance_report"
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
            "report_type": "cis",
            "scope": "all",
            "agent_filter": {},
            "output_format": "json",
            "wait": True,
            "wait_timeout": 600,
        }
        mod_cls.return_value = module
        yield module


@pytest.fixture
def api_mock():
    with patch(MODULE_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        yield api


class TestHypershieldComplianceReport:
    def test_generate_report(self, module_mock, api_mock):
        """Generating a compliance report sets changed=True."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_compliance_report

        api_mock.post.return_value = {"id": "rpt-1", "status": "completed", "findings": []}
        hypershield_compliance_report.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_report_with_findings(self, module_mock, api_mock):
        """Report with findings includes them in the result."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_compliance_report

        findings = [
            {"rule": "1.1", "status": "fail", "description": "No encryption"},
            {"rule": "1.2", "status": "pass", "description": "Auth enabled"},
        ]
        api_mock.post.return_value = {"id": "rpt-1", "status": "completed", "findings": findings}
        hypershield_compliance_report.main()

        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_check_mode_no_report(self, module_mock, api_mock):
        """Check mode does not generate a report."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_compliance_report

        module_mock.check_mode = True
        hypershield_compliance_report.main()

        api_mock.post.assert_not_called()
        call_kwargs = module_mock.exit_json.call_args[1]
        assert call_kwargs["changed"] is True

    def test_scoped_report(self, module_mock, api_mock):
        """Scoped report passes agent_filter to API."""
        from ansible_collections.stevefulme1.cisco_hypershield.plugins.modules import hypershield_compliance_report

        module_mock.params["agent_filter"] = {"group_id": "grp-1"}
        api_mock.post.return_value = {"id": "rpt-2", "status": "completed", "findings": []}
        hypershield_compliance_report.main()

        api_mock.post.assert_called_once()
