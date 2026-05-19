# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.error import HTTPError, URLError
from ansible.module_utils.six.moves.urllib.parse import urlencode


class HypershieldError(Exception):
    """Base exception for Hypershield operations."""

    def __init__(self, message, status_code=None, response_body=None):
        super(HypershieldError, self).__init__(message)
        self.message = message
        self.status_code = status_code
        self.response_body = response_body


class HypershieldAPIError(HypershieldError):
    """Exception raised when the Hypershield API returns an error."""
    pass


class HypershieldAPI(object):
    """Base class for interacting with the Cisco Hypershield REST API.

    Provides authenticated HTTP methods, pagination, and error handling
    for all Hypershield modules.
    """

    @staticmethod
    def hypershield_argument_spec():
        return dict(
            api_url=dict(type="str", required=True),
            api_key=dict(type="str", required=True, no_log=True),
            validate_certs=dict(type="bool", default=True),
            timeout=dict(type="int", default=30),
        )

    def __init__(self, module):
        """Initialize the API client from an AnsibleModule instance.

        Args:
            module: AnsibleModule with hypershield auth parameters.
        """
        self.module = module
        self.api_url = module.params["api_url"].rstrip("/")
        self.api_key = module.params["api_key"]
        self.validate_certs = module.params.get("validate_certs", True)
        self.timeout = module.params.get("timeout", 30)
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": self.api_key,
        }

    def _build_url(self, path, params=None):
        """Build a full URL from a path and optional query parameters.

        Args:
            path: API endpoint path (e.g., '/agents').
            params: Optional dict of query parameters.

        Returns:
            Fully qualified URL string.
        """
        url = "{0}/api/v1{1}".format(self.api_url, path)
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url = "{0}?{1}".format(url, urlencode(filtered))
        return url

    def _request(self, method, path, data=None, params=None):
        """Send an HTTP request to the Hypershield API.

        Args:
            method: HTTP method (GET, POST, PUT, PATCH, DELETE).
            path: API endpoint path.
            data: Optional request body dict.
            params: Optional query parameters dict.

        Returns:
            Parsed JSON response body as dict, or empty dict for 204.

        Raises:
            HypershieldAPIError: On HTTP errors from the API.
            HypershieldError: On connection or unexpected errors.
        """
        url = self._build_url(path, params)
        body = json.dumps(data) if data else None

        try:
            response = open_url(
                url,
                method=method,
                data=body,
                headers=self.headers,
                validate_certs=self.validate_certs,
                timeout=self.timeout,
            )
            status = response.getcode()
            if status == 204:
                return {}
            raw = response.read()
            return json.loads(raw) if raw else {}
        except HTTPError as e:
            status_code = e.code
            try:
                error_body = json.loads(e.read())
                msg = error_body.get("message", str(e))
            except Exception:
                msg = str(e)
            raise HypershieldAPIError(
                "API request {0} {1} failed ({2}): {3}".format(
                    method, path, status_code, msg
                ),
                status_code=status_code,
                response_body=msg,
            )
        except URLError as e:
            raise HypershieldError(
                "Connection error to {0}: {1}".format(url, str(e))
            )
        except Exception as e:
            raise HypershieldError(
                "Unexpected error during API request: {0}".format(str(e))
            )

    def get(self, path, params=None):
        """Send a GET request."""
        return self._request("GET", path, params=params)

    def post(self, path, data=None):
        """Send a POST request."""
        return self._request("POST", path, data=data)

    def put(self, path, data=None):
        """Send a PUT request."""
        return self._request("PUT", path, data=data)

    def patch(self, path, data=None):
        """Send a PATCH request."""
        return self._request("PATCH", path, data=data)

    def delete(self, path, params=None):
        """Send a DELETE request."""
        return self._request("DELETE", path, params=params)

    def list_paginated(self, path, params=None, key="items", limit=100):
        """Retrieve all pages of a paginated API endpoint.

        Args:
            path: API endpoint path.
            params: Optional query parameters dict.
            key: JSON key containing the list of items in each response.
            limit: Number of items per page.

        Returns:
            List of all items across all pages.
        """
        params = dict(params) if params else {}
        params["limit"] = limit
        params["offset"] = 0
        all_items = []

        while True:
            result = self.get(path, params=params)
            items = result.get(key, [])
            all_items.extend(items)
            total = result.get("total", len(all_items))
            if len(all_items) >= total or not items:
                break
            params["offset"] += limit

        return all_items

    def fail_json_from_error(self, error):
        """Fail the module with a HypershieldError.

        Args:
            error: HypershieldError instance.
        """
        self.module.fail_json(
            msg=error.message,
            status_code=getattr(error, "status_code", None),
            response_body=getattr(error, "response_body", None),
        )
