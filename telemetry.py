"""
telemetry.py
Auto-generates telemetry data from real video frame timestamps.
In production: streams from actual drone hardware via FlytBase APIs.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class TelemetryFrame:
    timestamp: str
    time_seconds: int
    location: str
    latitude: float
    longitude: float
    altitude: float
    battery: float
    drone_status: str
    is_night: bool


# Base coordinates (Pune, Maharashtra — example property)
BASE_LAT = 18.5204
BASE_LON = 73.8567

# Dynamic zone coordinates — 4 patrol zones around a property
LOCATION_COORDS = {
    "Zone A": (18.5204, 73.8567),
    "Zone B": (18.5210, 73.8570),
    "Zone C": (18.5220, 73.8575),
    "Zone D": (18.5195, 73.8560),
}

ALTITUDE_MAP = {
    "Zone A": 30.0,
    "Zone B": 25.0,
    "Zone C": 35.0,
    "Zone D": 40.0,
}


def generate_telemetry_from_frames(frames: list) -> List[TelemetryFrame]:
    """
    Auto-generates realistic telemetry for each extracted video frame.
    Battery drains over time, altitude varies by zone.
    Works with any video — zones are assigned dynamically.
    """
    total = len(frames)
    telemetry_list = []

    for i, frame in enumerate(frames):
        progress = i / max(total - 1, 1)  # 0.0 → 1.0
        battery = round(100.0 - (progress * 90), 1)  # 100% → 10%
        lat, lon = LOCATION_COORDS.get(frame["location"], (BASE_LAT, BASE_LON))
        altitude = ALTITUDE_MAP.get(frame["location"], 30.0)
        status = "returning" if battery < 15 else ("hovering" if i % 3 == 0 else "patrolling")

        telemetry_list.append(TelemetryFrame(
            timestamp=frame["timestamp"],
            time_seconds=int(frame["video_second"]),
            location=frame["location"],
            latitude=lat,
            longitude=lon,
            altitude=altitude,
            battery=battery,
            drone_status=status,
            is_night=frame["is_night"],
        ))

    return telemetry_list


# ── Legacy static data (kept for fallback/testing) ──────────────
def get_all_frames() -> list:
    """Legacy: returns static frame descriptions for testing without video."""
    return FRAME_DESCRIPTIONS

def get_all_telemetry() -> list:
    """Legacy: returns static telemetry for testing without video."""
    return TELEMETRY_DATA

def get_telemetry_stream():
    for t, f in zip(TELEMETRY_DATA, FRAME_DESCRIPTIONS):
        yield t, f


TELEMETRY_DATA = [
    TelemetryFrame("2026-06-14 08:00:00",    0, "Zone A", 18.5204, 73.8567, 30.0, 100.0, "patrolling", False),
    TelemetryFrame("2026-06-14 08:05:00",  300, "Zone B", 18.5210, 73.8570, 25.0,  98.0, "hovering",   False),
    TelemetryFrame("2026-06-14 08:10:00",  600, "Zone C", 18.5220, 73.8575, 35.0,  95.0, "patrolling", False),
    TelemetryFrame("2026-06-14 23:55:00",57300, "Zone A", 18.5204, 73.8567, 28.0,  15.0, "hovering",   True),
    TelemetryFrame("2026-06-15 00:01:00",57660, "Zone A", 18.5204, 73.8567, 28.0,  12.0, "hovering",   True),
]

# FIX: Added missing `video_second` and `is_night` fields to every static frame.
# Previously these fields were absent, which caused a KeyError when
# generate_telemetry_from_frames() or the video pipeline consumed these dicts,
# since both access frame["video_second"] and frame["is_night"] directly.
FRAME_DESCRIPTIONS = [
    {
        "frame_id": "F001",
        "timestamp": "2026-06-14 08:00:00",
        "location": "Zone A",
        "description": "Clear view of patrol zone A. No activity detected.",
        "video_second": 0,
        "is_night": False,
    },
    {
        "frame_id": "F002",
        "timestamp": "2026-06-14 08:05:00",
        "location": "Zone B",
        "description": "Blue Ford F150 truck parked in Zone B.",
        "video_second": 300,
        "is_night": False,
    },
    {
        "frame_id": "F003",
        "timestamp": "2026-06-14 08:10:00",
        "location": "Zone C",
        "description": "Two workers in yellow safety vests walking along Zone C perimeter.",
        "video_second": 600,
        "is_night": False,
    },
    {
        "frame_id": "F004",
        "timestamp": "2026-06-14 23:55:00",
        "location": "Zone A",
        "description": "Person in dark hoodie loitering in Zone A.",
        "video_second": 57300,
        "is_night": True,
    },
    {
        "frame_id": "F005",
        "timestamp": "2026-06-15 00:01:00",
        "location": "Zone A",
        "description": "Person attempting unauthorized access in Zone A. Possible break-in attempt.",
        "video_second": 57660,
        "is_night": True,
    },
]