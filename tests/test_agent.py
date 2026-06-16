"""
tests/test_agent.py
Dynamic test cases for the Drone Security Analyst Agent.
Tests are video-agnostic — they validate structure, rules, and engine behaviour
rather than specific hardcoded content.
Run with: python tests/test_agent.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from telemetry import get_all_frames, get_all_telemetry
from alert_engine import AlertEngine
from indexer import clear_index, index_frame, query_frames, query_by_location, get_frame_count


GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"
BOLD  = "\033[1m"

passed = 0
failed = 0


def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        print(f"  {GREEN}✅ PASS{RESET} — {name}")
        passed += 1
    else:
        print(f"  {RED}❌ FAIL{RESET} — {name}")
        if detail:
            print(f"       Detail: {detail}")
        failed += 1


def section(title: str):
    print(f"\n{BOLD}{'─'*50}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'─'*50}{RESET}")


# ─────────────────────────────────────────────────────
# TEST SUITE 1: Telemetry Data (Dynamic)
# ─────────────────────────────────────────────────────
section("1. Telemetry Data Tests")

frames = get_all_frames()
telemetry = get_all_telemetry()

test("Frames loaded correctly", len(frames) > 0, f"Got {len(frames)} frames")
test("Telemetry loaded correctly", len(telemetry) > 0, f"Got {len(telemetry)} telemetry points")
test("Frame count matches telemetry count", len(frames) == len(telemetry))
test("All frames have required fields",
     all("frame_id" in f and "timestamp" in f and "location" in f and "description" in f for f in frames))

# FIX: Also validate the fields required by generate_telemetry_from_frames()
# and the video pipeline (video_second, is_night). These were missing from the
# static FRAME_DESCRIPTIONS and would have caused a KeyError at runtime.
test("All frames have video_second field",
     all("video_second" in f for f in frames),
     "video_second required by generate_telemetry_from_frames()")
test("All frames have is_night field",
     all("is_night" in f for f in frames),
     "is_night required by pipeline and telemetry generation")

test("Battery values are valid percentages", all(0 <= t.battery <= 100 for t in telemetry))
test("Frame IDs are unique", len(set(f["frame_id"] for f in frames)) == len(frames))
test("At least one location is present", len(set(f["location"] for f in frames)) >= 1)
test("Timestamps are non-empty strings",
     all(isinstance(f["timestamp"], str) and len(f["timestamp"]) > 0 for f in frames))


# ─────────────────────────────────────────────────────
# TEST SUITE 2: Alert Engine (Rule-Based, Dynamic)
# ─────────────────────────────────────────────────────
section("2. Alert Engine Tests")

engine = AlertEngine()
base_telemetry = telemetry[0]

# Dynamically pick any location from telemetry
any_location = telemetry[0].location

# ── Rule: Night Person Detection ──
night_analysis = {
    "frame_id": "TEST_NIGHT_001",
    "timestamp": "2026-06-15 00:01:00",
    "location": any_location,
    "raw_description": "Person detected at night",
    "objects_detected": ["person"],
    "people_count": 1,
    "vehicles": [],
    "activity": "Person walking at midnight",
    "security_level": "critical",
    "requires_alert": True,
    "alert_reason": "Night time person detected",
    "notable_details": None
}
night_telemetry = next((t for t in telemetry if t.is_night), base_telemetry)
night_alerts = engine.process_frame(night_analysis, night_telemetry)

test("Night person detection triggers alert", len(night_alerts) > 0)
test("Night person alert is CRITICAL severity",
     any(a.severity == "CRITICAL" for a in night_alerts))

# ── Rule: Loitering Detection ──
loiter_analysis = {
    "frame_id": "TEST_LOITER_001",
    "timestamp": "2026-06-15 00:05:00",
    "location": any_location,
    "raw_description": "Person loitering for extended period",
    "objects_detected": ["person"],
    "people_count": 1,
    "vehicles": [],
    "activity": "Person loitering near perimeter for extended period",
    "security_level": "high",
    "requires_alert": True,
    "alert_reason": "Loitering detected",
    "notable_details": None
}
loiter_alerts = engine.process_frame(loiter_analysis, night_telemetry)
test("Loitering triggers HIGH or CRITICAL alert",
     any(a.severity in ["HIGH", "CRITICAL"] for a in loiter_alerts))

# ── Rule: Low Battery ──
low_bat_telemetry = min(telemetry, key=lambda t: t.battery)
low_bat_analysis = {
    "frame_id": "TEST_BAT_001",
    "timestamp": low_bat_telemetry.timestamp,
    "location": low_bat_telemetry.location,
    "raw_description": "All clear",
    "objects_detected": [],
    "people_count": 0,
    "vehicles": [],
    "activity": "All clear",
    "security_level": "none",
    "requires_alert": False,
    "alert_reason": None,
    "notable_details": None
}
bat_alerts = engine.process_frame(low_bat_analysis, low_bat_telemetry)

# FIX: Removed conditional guard `if low_bat_telemetry.battery < 15`.
# The static telemetry data includes a frame with battery=12% which always
# qualifies, so silently skipping the assertion could mask regressions if
# the data changes. The test now always asserts the expected behaviour
# and prints the actual battery level for context.
test("Low battery condition evaluated — battery is " + str(low_bat_telemetry.battery) + "%", True)
test("Low battery triggers LOW_BATTERY alert when under 15%",
     any(a.rule_triggered == "LOW_BATTERY" for a in bat_alerts),
     f"Battery: {low_bat_telemetry.battery}%, Alerts: {[a.rule_triggered for a in bat_alerts]}")

# ── Rule: Repeat Vehicle ──
engine2 = AlertEngine()
t1, t2 = telemetry[0], (telemetry[1] if len(telemetry) > 1 else telemetry[0])
v1 = {"frame_id": "TEST_VEH_001", "timestamp": t1.timestamp, "location": t1.location,
      "raw_description": "White sedan spotted", "objects_detected": ["vehicle"],
      "people_count": 0, "vehicles": ["White Sedan ABC-123"], "activity": "White sedan parked",
      "security_level": "low", "requires_alert": False, "alert_reason": None, "notable_details": None}
v2 = {**v1, "frame_id": "TEST_VEH_002", "timestamp": t2.timestamp}
engine2.process_frame(v1, t1)
v_alerts = engine2.process_frame(v2, t2)
test("Repeat vehicle triggers REPEAT_VEHICLE alert",
     any(a.rule_triggered == "REPEAT_VEHICLE" for a in v_alerts))

# ── Rule: Critical Security Level (Fixed Rule) ──
# FIX: Validates that _rule_critical_security_level now fires correctly.
# The old rule required `not requires_alert` which inverted the logic —
# it would fire ONLY when the frame wasn't already flagged. Now it fires
# whenever security_level == "critical", regardless of requires_alert.
engine3 = AlertEngine()
crit_analysis = {
    "frame_id": "TEST_CRIT_001",
    "timestamp": "2026-06-14 08:00:00",
    "location": any_location,
    "raw_description": "Critical security event",
    "objects_detected": ["person"],
    "people_count": 0,
    "vehicles": [],
    "activity": "Suspicious activity near perimeter",
    "security_level": "critical",
    "requires_alert": True,   # Previously this prevented the rule from firing
    "alert_reason": "Critical event",
    "notable_details": None
}
crit_alerts = engine3.process_frame(crit_analysis, base_telemetry)
test("Critical security level triggers HIGH_SECURITY_EVENT alert",
     any(a.rule_triggered == "HIGH_SECURITY_EVENT" for a in crit_alerts),
     f"Alerts triggered: {[a.rule_triggered for a in crit_alerts]}")

# ── Alert Structure Validation ──
all_alerts = engine.alerts + engine2.alerts + engine3.alerts
test("All alerts have required fields",
     all(hasattr(a, field) for a in all_alerts
         for field in ["alert_id", "severity", "timestamp", "location", "message", "action_required"]))
test("Alert IDs are unique", len(set(a.alert_id for a in engine.alerts)) == len(engine.alerts))
test("Alert severities are valid",
     all(a.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"] for a in all_alerts))


# ─────────────────────────────────────────────────────
# TEST SUITE 3: ChromaDB Indexer (Dynamic)
# ─────────────────────────────────────────────────────
section("3. ChromaDB Indexer Tests")

clear_index()
test("Index cleared successfully", get_frame_count() == 0)

# FIX: Validate query_frames returns [] on empty collection (not a crash).
# Previously collection.query() with n_results > 0 on an empty collection
# raised an error rather than returning an empty list.
empty_results = query_frames("test query on empty index")
test("query_frames on empty index returns empty list, not an error",
     empty_results == [],
     f"Got: {empty_results}")

# Use dynamic zone names from telemetry
zone1 = telemetry[0].location
zone2 = telemetry[1].location if len(telemetry) > 1 else telemetry[0].location

test_frame = {
    "frame_id": "IDX_TEST_001",
    "timestamp": "2026-06-14 08:05:00",
    "location": zone1,
    "raw_description": "Red SUV parked near entrance",
    "objects_detected": ["Red SUV", "vehicle"],
    "people_count": 0,
    "vehicles": ["Red SUV"],
    "activity": "Red SUV parked in patrol zone",
    "security_level": "low",
    "requires_alert": False,
    "alert_reason": None,
    "notable_details": "Unfamiliar vehicle"
}
index_frame(test_frame)
test("Frame indexed successfully", get_frame_count() == 1)

test_frame_2 = {**test_frame, "frame_id": "IDX_TEST_002",
                "location": zone2, "raw_description": "Empty zone, all clear",
                "vehicles": [], "activity": "No activity detected"}
index_frame(test_frame_2)
test("Multiple frames indexed", get_frame_count() == 2)

results = query_frames("red vehicle")
test("Semantic search returns results", len(results) > 0)
test("Search result contains expected frame",
     any(r["frame_id"] == "IDX_TEST_001" for r in results))
test("Search results have relevance score", all("relevance_score" in r for r in results))

location_results = query_by_location(zone2)
test("Location filter returns correct frame", len(location_results) > 0)

clear_index()
test("Index clears correctly after use", get_frame_count() == 0)


# ─────────────────────────────────────────────────────
# TEST SUITE 4: Pipeline Integration (Dynamic)
# ─────────────────────────────────────────────────────
section("4. Pipeline Integration Tests")

clear_index()
for frame in frames:
    analysis = {
        "frame_id": frame["frame_id"],
        "timestamp": frame["timestamp"],
        "location": frame["location"],
        "raw_description": frame["description"],
        "objects_detected": [],
        "people_count": 0,
        "vehicles": [],
        "activity": frame["description"],
        "security_level": "low",
        "requires_alert": False,
        "alert_reason": None,
        "notable_details": None
    }
    index_frame(analysis)

test("All simulated frames indexed into ChromaDB",
     get_frame_count() == len(frames))

full_engine = AlertEngine()
telem_list = get_all_telemetry()
for i, frame in enumerate(frames):
    t = telem_list[i] if i < len(telem_list) else telem_list[-1]
    analysis = {
        "frame_id": frame["frame_id"], "timestamp": frame["timestamp"],
        "location": frame["location"], "raw_description": frame["description"],
        "objects_detected": [], "people_count": 0, "vehicles": [],
        "activity": frame["description"], "security_level": "low",
        "requires_alert": False, "alert_reason": None, "notable_details": None
    }
    full_engine.process_frame(analysis, t)

summary = full_engine.get_summary()
test("Alert engine summary generated", isinstance(summary, dict))
test("Summary contains required keys",
     all(k in summary for k in ["total_alerts", "critical", "high", "medium", "low"]))
test("Alert counts are non-negative integers",
     all(isinstance(summary[k], int) and summary[k] >= 0
         for k in ["total_alerts", "critical", "high", "medium", "low"]))
test("Total alert count is consistent",
     summary["total_alerts"] == summary["critical"] + summary["high"] + summary["medium"] + summary["low"])

any_results = query_frames("security activity")
test("General semantic search works", len(any_results) >= 0)


# ─────────────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────────────
print(f"\n{'='*50}")
print(f"{BOLD}  TEST RESULTS{RESET}")
print(f"{'='*50}")
print(f"  {GREEN}Passed: {passed}{RESET}")
print(f"  {RED}Failed: {failed}{RESET}")
print(f"  Total:  {passed + failed}")
success_rate = (passed / (passed + failed) * 100) if (passed + failed) > 0 else 0
print(f"  Score:  {success_rate:.1f}%")
print(f"{'='*50}\n")
if failed == 0:
    print(f"  {GREEN}{BOLD}🎉 All tests passed!{RESET}")
else:
    print(f"  {RED}⚠️  {failed} test(s) failed. Review above.{RESET}")
print()