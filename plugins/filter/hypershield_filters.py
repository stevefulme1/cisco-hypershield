# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
name: hypershield_filters
short_description: Filter plugins for Cisco Hypershield data
version_added: "1.0.0"
description:
  - Collection of Jinja2 filters for working with Cisco Hypershield data.
  - Includes filters for CVE parsing, policy comparison, severity ranking,
    and agent status summarization.
author:
  - Steve Fulmer (@stevefulmer)
"""

import re


def parse_cve(data):
    """Extract CVE IDs from exploit protection data strings.

    Takes a string (or list of strings) from Hypershield exploit protection
    output and returns a deduplicated, sorted list of CVE identifiers.

    Args:
        data: A string or list of strings containing CVE references.

    Returns:
        Sorted list of unique CVE ID strings (e.g., ['CVE-2024-1234']).

    Examples:
        >>> parse_cve("Blocked exploit attempt for CVE-2024-1234 and CVE-2024-5678")
        ['CVE-2024-1234', 'CVE-2024-5678']
    """
    pattern = re.compile(r'CVE-\d{4}-\d{4,}')
    if isinstance(data, list):
        text = " ".join(str(item) for item in data)
    else:
        text = str(data)
    matches = pattern.findall(text)
    return sorted(set(matches))


def policy_diff(policy_a, policy_b):
    """Compare two policy dicts and return a list of differences.

    Performs a key-by-key comparison of two Hypershield policy dictionaries.
    Returns a list of difference descriptors showing what changed between
    policy_a and policy_b.

    Args:
        policy_a: First policy dict (the "before" state).
        policy_b: Second policy dict (the "after" state).

    Returns:
        List of dicts, each with keys: key, type, old, new.
        type is one of: 'added', 'removed', 'changed'.

    Examples:
        >>> policy_diff({"action": "allow"}, {"action": "deny"})
        [{'key': 'action', 'type': 'changed', 'old': 'allow', 'new': 'deny'}]
    """
    if not isinstance(policy_a, dict) or not isinstance(policy_b, dict):
        raise TypeError("policy_diff requires two dict arguments")

    differences = []
    all_keys = sorted(set(list(policy_a.keys()) + list(policy_b.keys())))

    for key in all_keys:
        if key not in policy_a:
            differences.append({
                "key": key,
                "type": "added",
                "old": None,
                "new": policy_b[key],
            })
        elif key not in policy_b:
            differences.append({
                "key": key,
                "type": "removed",
                "old": policy_a[key],
                "new": None,
            })
        elif policy_a[key] != policy_b[key]:
            differences.append({
                "key": key,
                "type": "changed",
                "old": policy_a[key],
                "new": policy_b[key],
            })

    return differences


def severity_rank(severity):
    """Convert a severity string to a numeric rank for sorting/comparison.

    Maps Hypershield severity labels to integer ranks where higher numbers
    indicate greater severity.

    Args:
        severity: Severity string (critical, high, medium, low, info).
                  Case-insensitive.

    Returns:
        Integer rank: critical=5, high=4, medium=3, low=2, info=1.
        Returns 0 for unknown severity strings.

    Examples:
        >>> severity_rank("critical")
        5
        >>> severity_rank("low")
        2
    """
    ranks = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }
    return ranks.get(str(severity).lower(), 0)


def agent_summary(agents):
    """Summarize a list of agent dicts into counts by status.

    Takes the output of hypershield_agent_info and produces a summary
    showing how many agents are in each status category.

    Args:
        agents: List of agent dicts, each expected to have a 'status' key.

    Returns:
        Dict mapping status strings to integer counts, plus a 'total' key.

    Examples:
        >>> agent_summary([{"status": "running"}, {"status": "running"}, {"status": "error"}])
        {'running': 2, 'error': 1, 'total': 3}
    """
    if not isinstance(agents, list):
        raise TypeError("agent_summary requires a list of agent dicts")

    summary = {"total": len(agents)}
    for agent in agents:
        status = agent.get("status", "unknown") if isinstance(agent, dict) else "unknown"
        status = str(status).lower()
        summary[status] = summary.get(status, 0) + 1

    return summary


class FilterModule(object):
    """Cisco Hypershield filter plugins."""

    def filters(self):
        """Return a dict mapping filter names to callables."""
        return {
            "parse_cve": parse_cve,
            "policy_diff": policy_diff,
            "severity_rank": severity_rank,
            "agent_summary": agent_summary,
        }
