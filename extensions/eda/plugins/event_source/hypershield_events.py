# -*- coding: utf-8 -*-
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Cisco Hypershield event source for Event-Driven Ansible.

Streams security events from the Hypershield management API using
Server-Sent Events (SSE) with automatic fallback to polling.
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r"""
---
name: hypershield_events
short_description: Stream security events from Cisco Hypershield
version_added: "1.0.0"
description:
  - Event source plugin for Event-Driven Ansible (EDA).
  - Connects to the Cisco Hypershield management API and streams security
    events in real time via Server-Sent Events (SSE).
  - Falls back to polling mode if SSE is not available.
  - Events are yielded with type, severity, source agent, details, and timestamp.
author:
  - Steve Fulmer (@stevefulmer)
options:
  api_url:
    description:
      - URL of the Cisco Hypershield management API.
    type: str
    required: true
  api_key:
    description:
      - API key for authenticating to the Hypershield management plane.
    type: str
    required: true
  event_types:
    description:
      - List of event types to subscribe to.
      - If not specified, all event types are received.
    type: list
    elements: str
    default: []
  severity_filter:
    description:
      - Minimum severity level for events.
      - Only events at or above this severity are yielded.
    type: str
    choices: [critical, high, medium, low, info]
    default: info
  poll_interval:
    description:
      - Interval in seconds between polling requests when SSE is unavailable.
    type: int
    default: 10
  validate_certs:
    description:
      - Whether to validate TLS certificates.
    type: bool
    default: true
"""

EXAMPLES = r"""
# In an EDA rulebook:
- name: Watch for critical Hypershield events
  hosts: all
  sources:
    - stevefulme1.cisco_hypershield.hypershield_events:
        api_url: https://hypershield.example.com
        api_key: "{{ HYPERSHIELD_API_KEY }}"
        event_types:
          - exploit_attempt
          - policy_violation
          - agent_status_change
        severity_filter: high
        poll_interval: 5
  rules:
    - name: React to exploit attempts
      condition: event.type == "exploit_attempt"
      action:
        run_playbook:
          name: respond_to_exploit.yml
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from urllib.parse import urlencode, urljoin

import aiohttp

logger = logging.getLogger("stevefulme1.cisco_hypershield.hypershield_events")

SEVERITY_RANKS = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def _meets_severity_threshold(event_severity, minimum_severity):
    """Check if an event severity meets the minimum threshold.

    Args:
        event_severity: Severity string from the event.
        minimum_severity: Minimum severity to pass through.

    Returns:
        True if the event meets or exceeds the threshold.
    """
    event_rank = SEVERITY_RANKS.get(str(event_severity).lower(), 0)
    min_rank = SEVERITY_RANKS.get(str(minimum_severity).lower(), 1)
    return event_rank >= min_rank


def _normalize_event(raw_event):
    """Normalize a raw API event into a standard EDA event dict.

    Args:
        raw_event: Raw event dict from the Hypershield API.

    Returns:
        Dict with keys: type, severity, source_agent, details, timestamp.
    """
    return {
        "type": raw_event.get("type", raw_event.get("event_type", "unknown")),
        "severity": raw_event.get("severity", "info"),
        "source_agent": raw_event.get("source_agent", raw_event.get("agent_id", "")),
        "details": raw_event.get("details", raw_event.get("data", {})),
        "timestamp": raw_event.get(
            "timestamp",
            datetime.now(timezone.utc).isoformat(),
        ),
    }


async def _stream_sse(session, url, headers, queue, event_types, severity_filter):
    """Stream events via Server-Sent Events.

    Args:
        session: aiohttp ClientSession.
        url: SSE endpoint URL.
        headers: Request headers dict.
        queue: asyncio.Queue to put received events into.
        event_types: List of event types to filter.
        severity_filter: Minimum severity string.

    Raises:
        aiohttp.ClientError: On connection failures.
    """
    async with session.get(url, headers=headers) as response:
        if response.status != 200:
            raise aiohttp.ClientError(
                "SSE connection failed with status {0}".format(response.status)
            )

        buffer = ""
        async for chunk in response.content.iter_any():
            buffer += chunk.decode("utf-8", errors="replace")

            while "\n\n" in buffer:
                message, buffer = buffer.split("\n\n", 1)
                data_lines = []
                for line in message.split("\n"):
                    if line.startswith("data:"):
                        data_lines.append(line[5:].strip())

                if not data_lines:
                    continue

                try:
                    raw = json.loads("".join(data_lines))
                except (json.JSONDecodeError, ValueError):
                    continue

                event = _normalize_event(raw)

                if event_types and event["type"] not in event_types:
                    continue
                if not _meets_severity_threshold(event["severity"], severity_filter):
                    continue

                await queue.put(event)


async def _poll_events(session, url, headers, queue, event_types,
                       severity_filter, poll_interval):
    """Poll for events when SSE is unavailable.

    Args:
        session: aiohttp ClientSession.
        url: Polling endpoint URL.
        headers: Request headers dict.
        queue: asyncio.Queue to put received events into.
        event_types: List of event types to filter.
        severity_filter: Minimum severity string.
        poll_interval: Seconds between poll requests.
    """
    last_timestamp = datetime.now(timezone.utc).isoformat()

    while True:
        params = {"since": last_timestamp, "limit": 100}
        if event_types:
            params["types"] = ",".join(event_types)

        poll_url = "{0}?{1}".format(url, urlencode(params))

        try:
            async with session.get(poll_url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    events = data.get("items", data.get("events", []))

                    for raw in events:
                        event = _normalize_event(raw)

                        if not _meets_severity_threshold(
                            event["severity"], severity_filter
                        ):
                            continue

                        await queue.put(event)

                        if event["timestamp"] > last_timestamp:
                            last_timestamp = event["timestamp"]
        except (aiohttp.ClientError, json.JSONDecodeError) as exc:
            logger.warning("Poll request failed: %s", exc)

        await asyncio.sleep(poll_interval)


async def main(queue, args):
    """Entry point for the EDA event source.

    Connects to the Hypershield API and streams security events into the
    provided asyncio queue. Attempts SSE first, falls back to polling.

    Args:
        queue: asyncio.Queue for yielding events to the EDA rulebook engine.
        args: Dict of plugin arguments matching the DOCUMENTATION options.
    """
    api_url = args["api_url"].rstrip("/")
    api_key = args["api_key"]
    event_types = args.get("event_types", [])
    severity_filter = args.get("severity_filter", "info")
    poll_interval = args.get("poll_interval", 10)
    validate_certs = args.get("validate_certs", True)

    headers = {
        "Accept": "text/event-stream",
        "X-API-Key": api_key,
    }

    ssl_context = None if validate_certs else False

    connector = aiohttp.TCPConnector(ssl=ssl_context)
    async with aiohttp.ClientSession(connector=connector) as session:
        sse_url = "{0}/api/v1/events/stream".format(api_url)

        try:
            logger.info("Attempting SSE connection to %s", sse_url)
            await _stream_sse(
                session, sse_url, headers, queue, event_types, severity_filter
            )
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            logger.warning(
                "SSE not available (%s), falling back to polling", exc
            )
            poll_url = "{0}/api/v1/events".format(api_url)
            headers["Accept"] = "application/json"
            await _poll_events(
                session, poll_url, headers, queue,
                event_types, severity_filter, poll_interval,
            )


if __name__ == "__main__":
    """Allow direct execution for testing."""

    class MockQueue:
        """Simple queue mock for testing."""

        async def put(self, event):
            print(json.dumps(event, indent=2))

    asyncio.run(
        main(
            MockQueue(),
            {
                "api_url": "https://hypershield.example.com",
                "api_key": "test-key",
                "event_types": [],
                "severity_filter": "info",
                "poll_interval": 10,
            },
        )
    )
