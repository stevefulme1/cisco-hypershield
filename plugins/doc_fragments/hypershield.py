# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):
    """Documentation fragment for Cisco Hypershield authentication."""

    DOCUMENTATION = r"""
options:
  api_url:
    description:
      - URL of the Cisco Hypershield management API.
      - Can also be set via the C(HYPERSHIELD_API_URL) environment variable.
    type: str
    required: true
  api_key:
    description:
      - API key for authenticating to the Hypershield management plane.
      - Can also be set via the C(HYPERSHIELD_API_KEY) environment variable.
    type: str
    required: true
    no_log: true
  validate_certs:
    description:
      - Whether to validate TLS certificates when connecting to the API.
    type: bool
    default: true
  timeout:
    description:
      - Timeout in seconds for API requests.
    type: int
    default: 30
"""
