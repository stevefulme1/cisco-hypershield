# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json

import pytest

from unittest.mock import MagicMock, patch


MODULE_UTILS_PATH = (
    "ansible_collections.stevefulme1.cisco_hypershield."
    "plugins.module_utils.hypershield"
)


@pytest.fixture
def mock_module():
    """Return a mock AnsibleModule with common defaults."""
    module = MagicMock()
    module.check_mode = False
    module.params = {
        "api_url": "https://hypershield.example.com",
        "api_key": "test-api-key",
        "validate_certs": True,
        "timeout": 30,
    }
    return module


@pytest.fixture
def mock_api(mock_module):
    """Return a mocked HypershieldAPI instance."""
    with patch(MODULE_UTILS_PATH + ".HypershieldAPI") as cls:
        api = MagicMock()
        cls.return_value = api
        api.module = mock_module
        yield api


@pytest.fixture
def module_args():
    """Return a helper that sets module args for AnsibleModule instantiation."""
    def _set_args(args):
        base = {
            "api_url": "https://hypershield.example.com",
            "api_key": "test-api-key",
            "validate_certs": True,
            "timeout": 30,
        }
        base.update(args)
        return json.dumps({"ANSIBLE_MODULE_ARGS": base})
    return _set_args


@pytest.fixture
def exit_json(mock_module):
    """Capture exit_json calls and return the mock."""
    mock_module.exit_json = MagicMock()
    return mock_module.exit_json


@pytest.fixture
def fail_json(mock_module):
    """Capture fail_json calls and return the mock."""
    mock_module.fail_json = MagicMock(side_effect=SystemExit(1))
    return mock_module.fail_json
