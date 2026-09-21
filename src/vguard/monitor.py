# src/vguard/monitor.py
import json
import os
import smtplib
import urllib.request
from dataclasses import dataclass, field
from email.mime.text import MIMEText
from typing import Callable, List


class AlertRoutingError(Exception):
    pass


@dataclass
class Alert:
    title: str
    details: dict = field(default_factory=dict)
    severity: str = "info"


class AlertRouter:
    def __init__(self):
        self._sinks: List[Callable[[Alert], None]] = [lambda alert: print(f"[vguard-alert] {alert.severity}: {alert.title}")]

    def add_console(self) -> None:
        self._sinks.append(lambda alert: print(f"[vguard-alert] {alert.severity}: {alert.title}"))

    def add_slack_webhook(self, url: str, channel: str = None) -> None:
        def sink(alert: Alert) -> None:
            body = {"text": f"[{alert.severity}] {alert.title}", "details": alert.details}
            if channel:
                body["channel"] = channel
            self._post(url, body)

        self._sinks.append(sink)

    def add_pagerduty(self, routing_key: str, service: str = "vguard") -> None:
        def sink(alert: Alert) -> None:
            body = {
                "routing_key": routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": alert.title,
                    "source": service,
                    "severity": alert.severity,
                    "custom_details": alert.details,
                },
            }
            self._post("https://events.pagerduty.com/v2/enqueue", body)

        self._sinks.append(sink)

    def add_email(self, smtp_host: str, smtp_port: int, sender: str, recipients: List[str], username: str = None, password: str = None) -> None:
        def sink(alert: Alert) -> None:
            message = MIMEText(json.dumps({"title": alert.title, "severity": alert.severity, "details": alert.details}, indent=2))
            message["Subject"] = f"[vguard:{alert.severity}] {alert.title}"
            message["From"] = sender
            message["To"] = ",".join(recipients)
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if username:
                    server.login(username, password or os.environ.get("VGUARD_SMTP_PASSWORD", ""))
                server.sendmail(sender, recipients, message.as_string())

        self._sinks.append(sink)

    def publish(self, alert: Alert) -> None:
        last_error = None
        for sink in self._sinks:
            try:
                sink(alert)
            except Exception as error:
                last_error = error
        if last_error is not None:
            raise AlertRoutingError(f"One or more alert sinks failed: {last_error}")

    @staticmethod
    def _post(url: str, body: dict) -> None:
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status not in (200, 202):
                raise AlertRoutingError(f"Alert endpoint returned HTTP {response.status}.")