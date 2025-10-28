#!/usr/bin/env python3
# Smart alert management: ALTO consolidation, quiet hours, escalation.

from datetime import datetime, timedelta
from collections import defaultdict


class AlertLevel:
    INFO = "INFO"
    ALTO = "ALTO"
    CRITICO = "CRITICO"


class AlertManager:
    def __init__(self):
        self.pending_alerts = defaultdict(list)
        self.last_consolidated = {}
        self.last_escalation = {}

    def classify_alert_level(self, parameter_a):
        if parameter_a < 50:
            return AlertLevel.INFO, "🟢", "Normal"
        elif parameter_a < 80:
            return AlertLevel.ALTO, "🟡", "Alto"
        else:
            return AlertLevel.CRITICO, "🔴", "Crítico"

    def is_quiet_hours(self):
        hour = datetime.now().hour
        return hour >= 22 or hour < 7

    def should_send_immediate_alert(self, alert_level):
        if alert_level == AlertLevel.CRITICO:
            return True
        if alert_level == AlertLevel.ALTO:
            return not self.is_quiet_hours()
        return False

    def should_consolidate_alert(self, project, alert_level):
        if alert_level != AlertLevel.ALTO:
            return False
        last_time = self.last_consolidated.get(project)
        if not last_time:
            return True
        time_since = (datetime.now() - last_time).total_seconds()
        return time_since >= 3600  # 1 hour

    def get_escalation_level(self, vm_key, alert_level, time_since_alert_seconds):
        if alert_level != AlertLevel.CRITICO:
            return "normal"
        minutes = time_since_alert_seconds / 60
        if minutes >= 30:
            return "director"
        elif minutes >= 10:
            return "supervisor"
        return "normal"

    def add_pending_alert(self, alert):
        project = alert.get('project', 'Unknown')
        self.pending_alerts[project].append(alert)

    def get_pending_alerts_for_project(self, project):
        return self.pending_alerts.get(project, [])

    def clear_pending_alerts(self, project):
        if project in self.pending_alerts:
            self.pending_alerts[project] = []
        self.last_consolidated[project] = datetime.now()

    def should_escalate(self, vm_key, time_since_alert_seconds):
        escalation_level = self.get_escalation_level(
            vm_key, AlertLevel.CRITICO, time_since_alert_seconds
        )
        last = self.last_escalation.get(vm_key)
        if escalation_level == "supervisor":
            if not last or (datetime.now() - last).total_seconds() >= 600:
                self.last_escalation[vm_key] = datetime.now()
                return True
        elif escalation_level == "director":
            if not last or (datetime.now() - last).total_seconds() >= 1800:
                self.last_escalation[vm_key] = datetime.now()
                return True
        return False

    def format_alert_body(self, alerts, project=None):
        if not alerts:
            return ""
        if len(alerts) == 1:
            return self._format_single_alert(alerts[0])
        return self._format_consolidated_alerts(alerts, project)

    def _format_single_alert(self, alert):
        level = alert['level']
        body = f"""{self._get_emoji(level)} ALERTA DE {level}

VM: {alert['display_name']} ({alert['vm_name']})
Proyecto: {alert['project']}
Worker: {alert['worker']}

MÉTRICAS:
• CPU: {alert['cpu_percent']:.1f}%
• vCPUs: {alert['metadata'].get('vcpus', 1)}
• Parámetro A: {alert['parameter_a']:.1f}
• Flavor: {alert['metadata'].get('flavor_name', 'Unknown')}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        return body

    def _format_consolidated_alerts(self, alerts, project):
        body = f"""🟡 ALERTA CONSOLIDADA

Proyecto: {project}
VMs ALTO: {len(alerts)}

DETALLE:
"""
        for i, alert in enumerate(alerts, 1):
            body += f"\n{i}. {alert['display_name']}\n"
            body += f"   CPU: {alert['cpu_percent']:.1f}% | A: {alert['parameter_a']:.1f}\n"
        body += f"\nTimestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        return body

    @staticmethod
    def _get_emoji(level):
        return {"CRITICO": "🔴", "ALTO": "🟡", "INFO": "🟢"}.get(level, "⚪")


def get_alert_subject(alert_level, display_name, project, is_consolidated=False):
    emoji = AlertManager._get_emoji(alert_level)
    if is_consolidated:
        return f"{emoji} [CONSOLIDADA] {project} - {alert_level}"
    return f"{emoji} [{alert_level}] {project}: {display_name}"
