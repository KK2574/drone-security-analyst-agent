"""
tools.py
LangGraph agent tools for the Drone Security Analyst.
Each tool allows the agent to query indexed frames, retrieve alerts,
track vehicles, and answer follow-up security questions.
"""

from langchain.tools import tool
from indexer import query_frames, query_by_location, query_by_security_level, query_alerts_only
import json

# Global references — set by main.py after processing
_alert_engine = None
_analyses = []
_summary = ""


def set_context(alert_engine, analyses: list, summary: str):
    """Called by main.py to inject processed data into tools"""
    global _alert_engine, _analyses, _summary
    _alert_engine = alert_engine
    _analyses = analyses
    _summary = summary


# ─────────────────────────────────────────────────────
# TOOL 1 — Search frames semantically
# ─────────────────────────────────────────────────────
@tool
def search_security_events(query: str) -> str:
    """
    Search all indexed drone footage frames using natural language.
    Examples: 'blue truck', 'person at night', 'loitering', 'vehicle in zone'
    """
    results = query_frames(query, n_results=5)
    if not results:
        return "No matching security events found."

    output = f"Found {len(results)} matching events for '{query}':\n\n"
    for r in results:
        output += f"📍 [{r['frame_id']}] {r['timestamp']} @ {r['location']}\n"
        output += f"   Activity: {r['activity']}\n"
        output += f"   Security Level: {r['security_level'].upper()}\n"
        if r['alert_reason']:
            output += f"   Alert: {r['alert_reason']}\n"
        output += f"   Relevance: {r['relevance_score']}\n\n"
    return output


# ─────────────────────────────────────────────────────
# TOOL 2 — Get all alerts
# ─────────────────────────────────────────────────────
@tool
def get_all_alerts(severity_filter: str = "all") -> str:
    """
    Retrieve all security alerts generated during the patrol.
    Optionally filter by severity: 'critical', 'high', 'medium', 'low', or 'all'
    """
    if _alert_engine is None:
        return "Alert engine not initialized."

    if severity_filter.lower() == "all":
        alerts = _alert_engine.alerts
    else:
        alerts = _alert_engine.get_alerts_by_severity(severity_filter.upper())

    if not alerts:
        return f"No {severity_filter} alerts found."

    output = f"🚨 {len(alerts)} Alert(s) [{severity_filter.upper()}]:\n\n"
    for alert in alerts:
        output += f"[{alert.alert_id}] {alert.severity} — {alert.timestamp}\n"
        output += f"  📍 Location: {alert.location}\n"
        output += f"  📋 {alert.message}\n"
        output += f"  ✅ Action: {alert.action_required}\n\n"
    return output


# ─────────────────────────────────────────────────────
# TOOL 3 — Track specific vehicle
# ─────────────────────────────────────────────────────
@tool
def track_vehicle(vehicle_description: str) -> str:
    """
    Track how many times a specific vehicle appeared and when.
    Example: 'Blue truck', 'white van', 'sedan'
    """
    results = query_frames(vehicle_description, n_results=10)
    vehicle_events = [r for r in results if r['relevance_score'] > 0.3]

    if not vehicle_events:
        return f"No events found for vehicle: {vehicle_description}"

    output = f"🚗 Vehicle Tracking Report: '{vehicle_description}'\n"
    output += f"   Total appearances: {len(vehicle_events)}\n\n"
    for i, event in enumerate(vehicle_events, 1):
        output += f"  Appearance {i}: {event['timestamp']} @ {event['location']}\n"
        output += f"  Activity: {event['activity']}\n\n"
    return output


# ─────────────────────────────────────────────────────
# TOOL 4 — Get location report
# ─────────────────────────────────────────────────────
@tool
def get_location_report(location: str) -> str:
    """
    Get all security events at a specific patrol zone.
    Zones are dynamically assigned: 'Zone A', 'Zone B', 'Zone C', 'Zone D'
    """
    frames = query_by_location(location)
    if not frames:
        return f"No events recorded at {location}"

    output = f"📍 Location Report: {location}\n"
    output += f"   Total events: {len(frames)}\n\n"
    for frame in frames:
        output += f"  [{frame['frame_id']}] {frame['timestamp']}\n"
        output += f"  Activity: {frame['activity']}\n"
        output += f"  Security Level: {frame['security_level'].upper()}\n\n"
    return output


# ─────────────────────────────────────────────────────
# TOOL 5 — Get daily security summary
# ─────────────────────────────────────────────────────
@tool
def get_daily_summary(query: str = "") -> str:
    """
    Get the AI-generated daily security summary for the entire patrol.
    Includes key events, patterns, and overall security assessment.
    """
    if not _summary:
        return "Daily summary not yet generated."

    alert_summary = _alert_engine.get_summary() if _alert_engine else {}

    output = "📊 DAILY SECURITY SUMMARY\n"
    output += "=" * 50 + "\n\n"
    output += _summary + "\n\n"
    output += "📈 Alert Statistics:\n"
    output += f"  Total Alerts: {alert_summary.get('total_alerts', 0)}\n"
    output += f"  🚨 Critical:  {alert_summary.get('critical', 0)}\n"
    output += f"  ⚠️  High:     {alert_summary.get('high', 0)}\n"
    output += f"  🔔 Medium:   {alert_summary.get('medium', 0)}\n"
    output += f"  ℹ️  Low:      {alert_summary.get('low', 0)}\n"
    return output


# ─────────────────────────────────────────────────────
# TOOL 6 — Answer follow-up questions (BONUS)
# ─────────────────────────────────────────────────────
@tool
def answer_security_question(question: str) -> str:
    """
    Answer any follow-up question about the day's security footage.
    Examples:
    - 'What objects were detected?'
    - 'How many people were seen?'
    - 'Was any vehicle seen more than once?'
    - 'What happened in Zone A?'

    FIX: Previously this tool just returned raw frame snippets as "context"
    without synthesising an actual answer, making it identical to
    search_security_events. It now builds a concise answer from the
    in-memory analyses and alert data so the agent gets a direct response.
    """
    if not _analyses:
        return "No footage has been processed yet. Please run the pipeline first."

    question_lower = question.lower()

    # ── People count ──────────────────────────────────
    if any(k in question_lower for k in ["how many people", "people count", "people detected", "persons"]):
        total_people = sum(a.get("people_count", 0) for a in _analyses)
        frames_with_people = [a for a in _analyses if a.get("people_count", 0) > 0]
        if total_people == 0:
            return "No people were detected across any frames during the patrol."
        lines = [f"👤 Total people detected: {total_people} across {len(frames_with_people)} frame(s).\n"]
        for a in frames_with_people:
            lines.append(f"  [{a['frame_id']}] {a['timestamp']} @ {a['location']}: {a.get('people_count')} person(s) — {a.get('activity', '')}")
        return "\n".join(lines)

    # ── Vehicles ──────────────────────────────────────
    if any(k in question_lower for k in ["vehicle", "truck", "van", "car", "sedan", "suv"]):
        vehicle_frames = [a for a in _analyses if a.get("vehicles")]
        if not vehicle_frames:
            return "No vehicles were detected during the patrol."
        seen: dict = {}
        for a in vehicle_frames:
            for v in a.get("vehicles", []):
                if v:
                    seen.setdefault(v, []).append(f"{a['timestamp']} @ {a['location']}")
        lines = [f"🚗 {len(seen)} unique vehicle(s) detected:\n"]
        for v, appearances in seen.items():
            lines.append(f"  • {v} — seen {len(appearances)} time(s): {'; '.join(appearances)}")
        return "\n".join(lines)

    # ── Objects ───────────────────────────────────────
    if any(k in question_lower for k in ["object", "what was detected", "what did"]):
        all_objects: dict = {}
        for a in _analyses:
            for obj in a.get("objects_detected", []):
                if obj and obj != "unknown":
                    all_objects[obj] = all_objects.get(obj, 0) + 1
        if not all_objects:
            return "No specific objects were detected during the patrol."
        lines = [f"📦 Objects detected across all frames:\n"]
        for obj, count in sorted(all_objects.items(), key=lambda x: -x[1]):
            lines.append(f"  • {obj}: {count} frame(s)")
        return "\n".join(lines)

    # ── Suspicious activity ───────────────────────────
    if any(k in question_lower for k in ["suspicious", "alert", "incident", "dangerous", "critical", "high"]):
        flagged = [a for a in _analyses if a.get("security_level") in ("critical", "high") or a.get("requires_alert")]
        if not flagged:
            return "No suspicious or high-security events were flagged during the patrol."
        lines = [f"⚠️  {len(flagged)} suspicious event(s) detected:\n"]
        for a in flagged:
            lines.append(f"  [{a['frame_id']}] {a['timestamp']} @ {a['location']} [{a.get('security_level','?').upper()}]")
            lines.append(f"    {a.get('activity','')}")
            if a.get("alert_reason"):
                lines.append(f"    Reason: {a['alert_reason']}")
        return "\n".join(lines)

    # ── Night activity ────────────────────────────────
    if any(k in question_lower for k in ["night", "midnight", "dark", "after hours"]):
        night_frames = [a for a in _analyses if a.get("is_night")]
        if not night_frames:
            return "No night-time frames were recorded during this patrol."
        lines = [f"🌙 {len(night_frames)} night-time frame(s):\n"]
        for a in night_frames:
            lines.append(f"  [{a['frame_id']}] {a['timestamp']} @ {a['location']}: {a.get('activity','')}")
        return "\n".join(lines)

    # ── Fallback: semantic search with synthesised summary ────────
    results = query_frames(question, n_results=6)
    if not results:
        return "No relevant footage found to answer this question."

    lines = [f"Based on drone footage analysis for '{question}':\n"]
    for r in results:
        lines.append(f"  [{r['frame_id']}] {r['timestamp']} @ {r['location']}: {r['activity']}")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────
# All tools — imported by main.py
# ─────────────────────────────────────────────────────
all_tools = [
    search_security_events,
    get_all_alerts,
    track_vehicle,
    get_location_report,
    get_daily_summary,
    answer_security_question,
]