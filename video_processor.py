"""
video_processor.py
Processes REAL video frames using OpenCV + Google Gemini Vision API.
Extracts frames at intervals, sends actual images to Gemini Vision,
and returns structured security intelligence per frame.
"""

import os
import cv2
import base64
import json
import time
from google import genai
from google.genai import types
from dotenv import load_dotenv

load_dotenv()

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
MODEL = "gemini-2.5-flash"

ANALYSIS_PROMPT = """
You are a security analyst AI reviewing drone surveillance footage.

Analyze this actual video frame image and extract structured security intelligence.

Location context: {location}
Timestamp: {timestamp}
Is Night Time: {is_night}
Frame number: {frame_num} of {total_frames}

Return ONLY a valid JSON object with this exact structure:
{{
    "objects_detected": ["list of objects seen e.g. person, blue Ford F150, white van, tree, building"],
    "people_count": 0,
    "vehicles": ["list of vehicles with color and type if visible"],
    "activity": "brief description of what is happening in the frame",
    "security_level": "none/low/medium/high/critical",
    "requires_alert": true or false,
    "alert_reason": "reason if requires_alert is true, else null",
    "notable_details": "any details useful for future reference e.g. repeat visitor, same vehicle, suspicious behaviour"
}}

Be precise and focus on security-relevant observations only.
"""


def extract_frames(video_path: str, interval_seconds: float = 2.5) -> list:
    """
    Extracts frames from a real video file at given interval.
    Returns list of dicts with frame_id, timestamp, image_b64, and position metadata.
    """
    if not os.path.exists(video_path):
        raise FileNotFoundError(f"Video not found: {video_path}")

    cap = cv2.VideoCapture(video_path)
    fps = cap.get(cv2.CAP_PROP_FPS)
    total_video_seconds = cap.get(cv2.CAP_PROP_FRAME_COUNT) / fps

    print(f"   📹 Video loaded: {total_video_seconds:.1f}s duration, {fps:.1f} FPS")
    print(f"   🖼️  Extracting 1 frame every {interval_seconds}s...")

    frames = []
    frame_idx = 0
    second = 0.0

    # Location mapping based on video timestamp
    location_map = _build_location_map(total_video_seconds)

    while second <= total_video_seconds:
        cap.set(cv2.CAP_PROP_POS_MSEC, second * 1000)
        ret, frame = cap.read()
        if not ret:
            break

        # Encode frame as JPEG → base64
        _, buffer = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 85])
        image_b64 = base64.b64encode(buffer).decode('utf-8')

        # Map video second to a simulated real-world timestamp + location
        location = _get_location(second, location_map)
        timestamp = _second_to_timestamp(second)
        is_night = _is_night(second, total_video_seconds)

        frame_idx += 1
        frames.append({
            "frame_id": f"F{frame_idx:03d}",
            "frame_num": frame_idx,
            "video_second": round(second, 1),
            "timestamp": timestamp,
            "location": location,
            "is_night": is_night,
            "image_b64": image_b64,
        })

        print(f"   ✅ Extracted frame F{frame_idx:03d} @ {second:.1f}s → {location}")
        second += interval_seconds

    cap.release()
    print(f"   📸 Total frames extracted: {len(frames)}\n")
    return frames


def analyze_frame(frame: dict, total_frames: int = 1) -> dict:
    """
    Sends actual image frame to Gemini Vision for security analysis.
    Returns structured intelligence about the frame.
    """
    prompt = ANALYSIS_PROMPT.format(
        location=frame["location"],
        timestamp=frame["timestamp"],
        is_night=frame.get("is_night", False),
        frame_num=frame["frame_num"],
        total_frames=total_frames
    )

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=MODEL,
                contents=[
                    types.Part.from_bytes(
                        data=base64.b64decode(frame["image_b64"]),
                        mime_type="image/jpeg"
                    ),
                    prompt
                ],
                config=types.GenerateContentConfig(
                    response_mime_type="application/json"
                )
            )

            raw = response.text.strip()
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0].strip()
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0].strip()

            analysis = json.loads(raw)
            analysis["frame_id"] = frame["frame_id"]
            analysis["timestamp"] = frame["timestamp"]
            analysis["location"] = frame["location"]
            analysis["video_second"] = frame["video_second"]
            analysis["raw_description"] = analysis.get("activity", "")
            return analysis

        except Exception as e:
            err = str(e)
            if "429" in err:
                wait = 30 + (attempt * 15)
                print(f"  ⏳ Rate limit — waiting {wait}s (attempt {attempt+1}/3)...")
                time.sleep(wait)
            else:
                print(f"  ⚠️  Gemini error for {frame['frame_id']}: {e}")
                return _fallback_analysis(frame)

    print(f"  ⚠️  Gemini failed after 3 retries for {frame['frame_id']} — using fallback")
    return _fallback_analysis(frame)


def analyze_batch(frames: list, telemetry_list: list = None) -> list:
    """
    Analyses all extracted video frames with Gemini Vision.
    Adds delay between calls to respect rate limits.
    """
    results = []
    total = len(frames)

    for i, frame in enumerate(frames):
        print(f"  🔍 Analysing {frame['frame_id']} @ {frame['location']} ({frame['timestamp']})...")
        analysis = analyze_frame(frame, total_frames=total)
        results.append(analysis)

        # Polite delay between API calls
        if i < total - 1:
            time.sleep(3)

    return results


def generate_video_summary(analyses: list) -> str:
    """
    BONUS: Generates a concise 1-paragraph summary of all security events.
    """
    events = [
        f"{a['timestamp']} at {a['location']}: {a.get('activity', 'No activity')}"
        for a in analyses
    ]
    events_text = "\n".join(events)

    prompt = f"""
You are a professional security analyst. Based on these drone surveillance events from a patrol:

{events_text}

Generate ONE concise paragraph (3-4 sentences) summarizing:
- Key security events and objects detected
- Any suspicious patterns or repeated activity
- Overall security assessment

Be direct and professional.
"""
    for attempt in range(3):
        try:
            response = client.models.generate_content(model=MODEL, contents=prompt)
            return response.text.strip()
        except Exception as e:
            if "429" in str(e):
                wait = 30 + (attempt * 15)
                print(f"  ⏳ Rate limit — waiting {wait}s...")
                time.sleep(wait)
            else:
                return f"Summary unavailable: {e}"

    return "Summary unavailable after retries."


# ── Private Helpers ──────────────────────────────────────────────

def _build_location_map(total_seconds: float) -> list:
    """Divides video into 4 equal patrol zones dynamically based on video length."""
    segment = total_seconds / 4
    return [
        (0,              segment,       "Zone A"),
        (segment,        segment * 2,   "Zone B"),
        (segment * 2,    segment * 3,   "Zone C"),
        (segment * 3,    total_seconds, "Zone D"),
    ]

def _get_location(second: float, location_map: list) -> str:
    for start, end, loc in location_map:
        if start <= second < end:
            return loc
    return "Zone A"

def _second_to_timestamp(second: float) -> str:
    """Maps video seconds to a simulated 24h patrol timestamp."""
    from datetime import datetime, timedelta
    base = datetime(2026, 6, 14, 8, 0, 0)
    simulated = base + timedelta(hours=second * (16 / 60))  # scale 60s video → 16h patrol
    return simulated.strftime("%Y-%m-%d %H:%M:%S")

def _is_night(second: float, total_seconds: float) -> bool:
    """Last 20% of video = night patrol."""
    return second >= total_seconds * 0.8

def _fallback_analysis(frame: dict) -> dict:
    return {
        "frame_id": frame["frame_id"],
        "timestamp": frame["timestamp"],
        "location": frame["location"],
        "video_second": frame.get("video_second", 0),
        "raw_description": "Analysis unavailable",
        "objects_detected": ["unknown"],
        "people_count": 0,
        "vehicles": [],
        "activity": "Frame analysis failed — fallback used",
        "security_level": "low",
        "requires_alert": False,
        "alert_reason": None,
        "notable_details": None,
    }