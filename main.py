"""
main.py
Drone Security Analyst Agent — Main Orchestration
Processes REAL video via OpenCV + Gemini Vision through:
1. Real frame extraction (OpenCV)
2. Gemini Vision analysis (actual images)
3. ChromaDB frame indexing
4. Smart alert engine
5. LangGraph conversational agent
"""

import os
import sys
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent

from telemetry import generate_telemetry_from_frames, get_all_frames, get_all_telemetry
from video_processor import extract_frames, analyze_batch, generate_video_summary
from indexer import index_all_frames, clear_index, get_frame_count
from alert_engine import AlertEngine
import tools as agent_tools

load_dotenv()

DEFAULT_VIDEO = "security_footage.mp4"
FRAME_INTERVAL = 2.5


def print_banner(mode: str):
    print("\n" + "="*65)
    print("   🚁  DRONE SECURITY ANALYST AGENT  🚁")
    print(f"   Mode: {mode}")
    print("   Powered by Gemini Vision + LangGraph + ChromaDB")
    print("="*65 + "\n")


def extract_text(content) -> str:
    """Safely extracts plain text from Gemini agent response."""
    if isinstance(content, list):
        return " ".join(c.get("text", "") for c in content if isinstance(c, dict))
    return str(content)


def run_pipeline(video_path: str = None):
    use_real_video = video_path and os.path.exists(video_path)
    mode = f"Real Video: {video_path}" if use_real_video else "Simulated Frames"
    print_banner(mode)

    print("📡 Step 1: Loading drone telemetry and video frames...")
    if use_real_video:
        frames = extract_frames(video_path, interval_seconds=FRAME_INTERVAL)
        telemetry_list = generate_telemetry_from_frames(frames)
        print(f"   ✅ Extracted {len(frames)} real frames from video")
        print(f"   📍 Zones covered: {list(set(f['location'] for f in frames))}\n")
    else:
        print("   ⚠️  No video file found — using simulated frames")
        frames = get_all_frames()
        telemetry_list = get_all_telemetry()
        print(f"   ✅ Loaded {len(frames)} simulated frames\n")

    print("🔍 Step 2: Analysing frames with Gemini Vision...")
    analyses = analyze_batch(frames, telemetry_list)
    print(f"\n   ✅ Analysed {len(analyses)} frames\n")

    print("📦 Step 3: Indexing frames into ChromaDB...")
    clear_index()
    index_all_frames(analyses)
    print(f"   ✅ {get_frame_count()} frames indexed and queryable\n")

    print("🚨 Step 4: Running security alert engine...")
    engine = AlertEngine()
    alerts = engine.process_all_frames(analyses, telemetry_list)
    summary_stats = engine.get_summary()
    print(f"\n   ✅ Alert engine complete:")
    print(f"      Total alerts : {summary_stats['total_alerts']}")
    print(f"      🚨 Critical  : {summary_stats['critical']}")
    print(f"      ⚠️  High     : {summary_stats['high']}")
    print(f"      🔔 Medium    : {summary_stats['medium']}")
    print(f"      ℹ️  Low      : {summary_stats['low']}\n")

    print("📊 Step 5: Generating AI daily security summary...")
    daily_summary = generate_video_summary(analyses)
    print(f"\n{'='*65}")
    print("📋 DAILY SECURITY SUMMARY:")
    print(f"{'='*65}")
    print(daily_summary)
    print(f"{'='*65}\n")

    if alerts:
        print("\n🚨 SECURITY ALERTS GENERATED:")
        print("="*65)
        for alert in alerts:
            icons = {"CRITICAL": "🚨", "HIGH": "⚠️ ", "MEDIUM": "🔔", "LOW": "ℹ️ "}
            icon = icons.get(alert.severity, "🔔")
            print(f"\n{icon} [{alert.alert_id}] {alert.severity}")
            print(f"   Time     : {alert.timestamp}")
            print(f"   Location : {alert.location}")
            print(f"   {alert.message}")
            print(f"   Action   : {alert.action_required}")
        print("\n" + "="*65)
    else:
        print("✅ No security alerts triggered.")

    return engine, analyses, daily_summary


def run_agent(engine, analyses, daily_summary):
    agent_tools.set_context(engine, analyses, daily_summary)

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0,
        google_api_key=os.getenv("GEMINI_API_KEY")
    )

    agent = create_react_agent(llm, agent_tools.all_tools)

    print("\n\n🤖 SECURITY ANALYST AGENT — Interactive Mode")
    print("="*65)
    print("Ask me anything about today's drone surveillance footage.")
    print("Examples:")
    print("  • 'Show me all critical alerts'")
    print("  • 'What vehicles were detected?'")
    print("  • 'What happened in Zone A?'")
    print("  • 'Give me the daily security summary'")
    print("  • 'Were there any people detected?'")
    print("\nType 'quit' to exit.\n")
    print("="*65 + "\n")

    demo_queries = [
        "Give me the daily security summary",
        "What objects and vehicles were detected?",
        "Show me all critical alerts",
        "Were there any suspicious activities?",
    ]

    print("🔄 Running demo queries...\n")
    for query in demo_queries:
        print(f"\n❓ QUERY: {query}")
        print("-" * 50)
        result = agent.invoke({"messages": [{"role": "user", "content": query}]})
        print(f"✅ {extract_text(result['messages'][-1].content)}")

    print("\n" + "="*65)
    print("💬 Now entering interactive mode! (BONUS: ask any follow-up question)")
    print("="*65 + "\n")

    while True:
        user_input = input("❓ Your question: ").strip()
        if user_input.lower() in ["quit", "exit", "q"]:
            print("👋 Agent shutting down. Stay secure!")
            break
        if not user_input:
            continue
        result = agent.invoke({"messages": [{"role": "user", "content": user_input}]})
        print(f"\n✅ {extract_text(result['messages'][-1].content)}\n")


if __name__ == "__main__":
    video_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VIDEO
    engine, analyses, daily_summary = run_pipeline(video_path)
    run_agent(engine, analyses, daily_summary)