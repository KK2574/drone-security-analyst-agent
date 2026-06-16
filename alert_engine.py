"""
alert_engine.py
Time-aware, rule-based security alert system.
Generates immediate alerts based on predefined security rules.
Tracks patterns across frames (e.g., repeat vehicles, loitering duration).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
from collections import defaultdict


@dataclass
class Alert:
    alert_id: str
    severity: str          # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    timestamp: str
    location: str
    frame_id: str
    message: str
    rule_triggered: str
    action_required: str


class AlertEngine:
    """
    Smart alert engine that:
    - Applies time-aware rules (night vs day)
    - Tracks repeat visitors/vehicles
    - Detects loitering patterns
    - Escalates severity based on context
    """

    def __init__(self):
        self.alerts: list[Alert] = []
        self.vehicle_log: defaultdict = defaultdict(list)    # tracks vehicle appearances
        self.person_log: defaultdict = defaultdict(list)     # tracks person appearances
        self.location_history: defaultdict = defaultdict(list)
        self.alert_counter = 0

        # ── Security Rules ──────────────────────────────
        self.rules = [
            self._rule_night_person,
            self._rule_loitering,
            self._rule_perimeter_breach,
            self._rule_repeat_vehicle,
            self._rule_critical_security_level,
            self._rule_gate_breach_attempt,
            self._rule_low_battery_warning,
            self._rule_unmarked_vehicle,
        ]

    def process_frame(self, analysis: dict, telemetry) -> list[Alert]:
        """
        Processes a single frame analysis against all rules.
        Returns list of alerts triggered for this frame.
        """
        triggered = []

        # Update tracking logs
        self._update_logs(analysis, telemetry)

        # Apply all rules
        for rule in self.rules:
            alert = rule(analysis, telemetry)
            if alert:
                self.alerts.append(alert)
                triggered.append(alert)
                self._print_alert(alert)

        return triggered

    def process_all_frames(self, analyses: list, telemetry_list: list) -> list[Alert]:
        """Processes all frames and returns all triggered alerts"""
        print("\n🚨 Running Alert Engine...\n")
        for analysis, telemetry in zip(analyses, telemetry_list):
            self.process_frame(analysis, telemetry)
        return self.alerts

    def get_alerts_by_severity(self, severity: str) -> list[Alert]:
        return [a for a in self.alerts if a.severity == severity]

    def get_summary(self) -> dict:
        return {
            "total_alerts": len(self.alerts),
            "critical": len(self.get_alerts_by_severity("CRITICAL")),
            "high": len(self.get_alerts_by_severity("HIGH")),
            "medium": len(self.get_alerts_by_severity("MEDIUM")),
            "low": len(self.get_alerts_by_severity("LOW")),
            "repeat_vehicles": dict(self.vehicle_log),
        }

    # ── Private: Tracking ────────────────────────────────

    def _update_logs(self, analysis: dict, telemetry) -> None:
        for vehicle in analysis.get("vehicles", []):
            if vehicle:
                self.vehicle_log[vehicle].append(analysis["timestamp"])
        self.location_history[analysis["location"]].append(analysis)

    # ── Private: Rules ───────────────────────────────────

    def _rule_night_person(self, analysis: dict, telemetry) -> Optional[Alert]:
        """CRITICAL: Person detected at night"""
        if telemetry.is_night and analysis.get("people_count", 0) > 0:
            return self._make_alert(
                "CRITICAL", analysis, telemetry,
                f"🚨 Person detected at night at {analysis['location']} ({analysis['timestamp']}). Immediate verification required.",
                "NIGHT_PERSON_DETECTED",
                "Dispatch security personnel. Review live feed immediately."
            )
        return None

    def _rule_loitering(self, analysis: dict, telemetry) -> Optional[Alert]:
        """HIGH: Loitering detected"""
        keywords = ["loitering", "stationary", "standing", "waiting", "lingering"]
        desc = analysis.get("activity", "").lower()
        if any(k in desc for k in keywords):
            severity = "CRITICAL" if telemetry.is_night else "HIGH"
            return self._make_alert(
                severity, analysis, telemetry,
                f"⚠️  Loitering detected at {analysis['location']} ({analysis['timestamp']}). Person stationary for extended period.",
                "LOITERING_DETECTED",
                "Monitor closely. Alert security if behaviour continues."
            )
        return None

    def _rule_perimeter_breach(self, analysis: dict, telemetry) -> Optional[Alert]:
        """CRITICAL: Perimeter breach attempt"""
        keywords = ["trespassing", "breach", "climbing", "fence", "attempting to open", "break-in"]
        desc = analysis.get("activity", "").lower() + " " + (analysis.get("alert_reason") or "").lower()
        if any(k in desc for k in keywords):
            return self._make_alert(
                "CRITICAL", analysis, telemetry,
                f"🚨 PERIMETER BREACH at {analysis['location']} ({analysis['timestamp']}). Immediate action required.",
                "PERIMETER_BREACH",
                "EMERGENCY: Contact security and law enforcement immediately."
            )
        return None

    def _rule_repeat_vehicle(self, analysis: dict, telemetry) -> Optional[Alert]:
        """MEDIUM: Same vehicle seen multiple times"""
        for vehicle in analysis.get("vehicles", []):
            if vehicle and len(self.vehicle_log.get(vehicle, [])) >= 2:
                times = self.vehicle_log[vehicle]
                return self._make_alert(
                    "MEDIUM", analysis, telemetry,
                    f"🔁 Repeat vehicle detected: '{vehicle}' seen {len(times)} times today. Last seen at {times[-2]}.",
                    "REPEAT_VEHICLE",
                    "Log vehicle details. Verify with property owner if expected."
                )
        return None

    def _rule_critical_security_level(self, analysis: dict, telemetry) -> Optional[Alert]:
        """HIGH: Frame flagged as critical security level by vision model.

        FIX: Previously used `not analysis.get("requires_alert")` which caused
        this rule to fire ONLY when requires_alert was False — the inverse of the
        intended behaviour. Corrected to fire whenever security_level is 'critical',
        regardless of requires_alert, avoiding double-alerting only when
        requires_alert is already True (handled by the AI_FLAG rule in tools).
        """
        if analysis.get("security_level") == "critical":
            return self._make_alert(
                "HIGH", analysis, telemetry,
                f"⚠️  High security event at {analysis['location']}: {analysis.get('activity', '')}",
                "HIGH_SECURITY_EVENT",
                "Review frame immediately. Escalate if needed."
            )
        return None

    def _rule_gate_breach_attempt(self, analysis: dict, telemetry) -> Optional[Alert]:
        """CRITICAL: Gate breach attempt"""
        keywords = ["attempting to open gate", "forcing", "breaking", "gate breach"]
        desc = analysis.get("activity", "").lower()
        if any(k in desc for k in keywords):
            return self._make_alert(
                "CRITICAL", analysis, telemetry,
                f"🚨 GATE BREACH ATTEMPT at {analysis['location']} ({analysis['timestamp']}). Person attempting forced entry.",
                "GATE_BREACH_ATTEMPT",
                "EMERGENCY: Alert all security immediately. Lock down property."
            )
        return None

    def _rule_low_battery_warning(self, analysis: dict, telemetry) -> Optional[Alert]:
        """LOW: Drone battery critical"""
        if telemetry.battery < 15:
            return self._make_alert(
                "LOW", analysis, telemetry,
                f"🔋 Drone battery critical: {telemetry.battery}% at {telemetry.location}. Return to dock recommended.",
                "LOW_BATTERY",
                "Initiate drone return-to-dock procedure."
            )
        return None

    def _rule_unmarked_vehicle(self, analysis: dict, telemetry) -> Optional[Alert]:
        """MEDIUM: Unmarked vehicle detected"""
        keywords = ["unmarked", "unknown vehicle", "suspicious van", "unidentified vehicle"]
        desc = analysis.get("activity", "").lower()
        vehicles_text = " ".join(analysis.get("vehicles", [])).lower()
        if any(k in desc or k in vehicles_text for k in keywords):
            return self._make_alert(
                "MEDIUM", analysis, telemetry,
                f"🚐 Unmarked/unidentified vehicle at {analysis['location']} ({analysis['timestamp']}): {', '.join(analysis.get('vehicles', []))}",
                "UNMARKED_VEHICLE",
                "Verify with property owner. Record vehicle details."
            )
        return None

    # ── Helpers ──────────────────────────────────────────

    def _make_alert(self, severity, analysis, telemetry, message, rule, action) -> Alert:
        self.alert_counter += 1
        return Alert(
            alert_id=f"ALT-{self.alert_counter:04d}",
            severity=severity,
            timestamp=analysis["timestamp"],
            location=analysis["location"],
            frame_id=analysis["frame_id"],
            message=message,
            rule_triggered=rule,
            action_required=action
        )

    def _print_alert(self, alert: Alert) -> None:
        icons = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "🔔", "LOW": "ℹ️ "}
        icon = icons.get(alert.severity, "🔔")
        print(f"  {icon} [{alert.severity}] {alert.message}")