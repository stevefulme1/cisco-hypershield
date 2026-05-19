# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Cisco Hypershield severity filter for Event-Driven Ansible.

Filters events by minimum severity threshold, dropping events below
the configured level.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
name: severity_filter
short_description: Filter Hypershield events by minimum severity
version_added: "1.0.0"
description:
  - Event filter plugin for Event-Driven Ansible (EDA).
  - Filters incoming events based on a minimum severity threshold.
  - Events below the threshold are dropped (None is returned).
  - Severity levels in descending order are critical, high, medium, low.
author:
  - Steve Fulmer (@stevefulmer)
options:
  minimum_severity:
    description:
      - Minimum severity level to pass through.
      - Events with severity below this threshold are dropped.
    type: str
    choices: [critical, high, medium, low]
    default: low
"""

EXAMPLES = r"""
# In an EDA rulebook:
- name: Process only high-severity Hypershield events
  hosts: all
  sources:
    - stevefulme1.cisco_hypershield.hypershield_events:
        api_url: https://hypershield.example.com
        api_key: "{{ HYPERSHIELD_API_KEY }}"
  event_filters:
    - stevefulme1.cisco_hypershield.severity_filter:
        minimum_severity: high
  rules:
    - name: Handle critical or high severity events
      condition: event.type is defined
      action:
        run_playbook:
          name: remediate.yml
"""

SEVERITY_RANKS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


def main(event, minimum_severity="low"):
    """Filter events by minimum severity threshold.

    Compares the event's severity against the configured minimum and
    returns the event only if it meets or exceeds the threshold.

    Args:
        event: Dict representing the incoming event. Expected to have
               a 'severity' key with a string value.
        minimum_severity: Minimum severity to pass through. One of
                          critical, high, medium, low. Defaults to low.

    Returns:
        The event dict if severity meets the threshold, None otherwise.
    """
    if not isinstance(event, dict):
        return event

    event_severity = event.get("severity", "")
    if not event_severity:
        # Events without severity pass through (don't silently drop)
        return event

    event_rank = SEVERITY_RANKS.get(str(event_severity).lower(), 0)
    min_rank = SEVERITY_RANKS.get(str(minimum_severity).lower(), 1)

    if event_rank >= min_rank:
        return event

    return None
