"""
indexer.py
Frame-by-frame indexing system using ChromaDB vector database.
Stores each frame analysis with embeddings for semantic search.
Query by time, location, object type, or security level.
"""

import chromadb
from chromadb.config import Settings
import json
from datetime import datetime


# ─────────────────────────────────────────────────────
# ChromaDB setup — persistent local storage
# ─────────────────────────────────────────────────────
client = chromadb.PersistentClient(path="./chroma_db")
collection = client.get_or_create_collection(
    name="drone_security_frames",
    metadata={"hnsw:space": "cosine"}
)


def index_frame(analysis: dict) -> None:
    """
    Indexes a single frame analysis into ChromaDB.
    Stores full analysis as metadata + searchable text document.
    """
    # Build rich searchable text for embedding
    objects = ", ".join(analysis.get("objects_detected", []))
    vehicles = ", ".join(analysis.get("vehicles", []))

    searchable_text = f"""
    Frame {analysis['frame_id']} at {analysis['location']} on {analysis['timestamp']}.
    Objects: {objects}.
    Vehicles: {vehicles}.
    Activity: {analysis.get('activity', '')}.
    Security level: {analysis.get('security_level', 'none')}.
    Details: {analysis.get('notable_details', '')}.
    Alert: {analysis.get('alert_reason', 'none')}.
    """

    # Store with metadata for filtering
    collection.add(
        documents=[searchable_text.strip()],
        metadatas=[{
            "frame_id": analysis["frame_id"],
            "timestamp": analysis["timestamp"],
            "location": analysis["location"],
            "security_level": analysis.get("security_level", "none"),
            "requires_alert": str(analysis.get("requires_alert", False)),
            "people_count": str(analysis.get("people_count", 0)),
            "vehicles": json.dumps(analysis.get("vehicles", [])),
            "objects": json.dumps(analysis.get("objects_detected", [])),
            "activity": analysis.get("activity", ""),
            "alert_reason": analysis.get("alert_reason", "") or "",
        }],
        ids=[analysis["frame_id"]]
    )


def index_all_frames(analyses: list) -> None:
    """Indexes all frame analyses into ChromaDB"""
    print(f"\n📦 Indexing {len(analyses)} frames into ChromaDB...")
    for analysis in analyses:
        index_frame(analysis)
        print(f"  ✅ Indexed {analysis['frame_id']} @ {analysis['location']}")
    print(f"📦 All frames indexed successfully!\n")


def query_frames(query: str, n_results: int = 5) -> list:
    """
    Semantic search over all indexed frames.
    e.g. query="blue truck at garage" returns relevant frames.

    FIX: Guard against empty collection — ChromaDB raises an error
    if n_results > 0 but the collection is empty.
    """
    count = collection.count()
    if count == 0:
        return []

    results = collection.query(
        query_texts=[query],
        n_results=min(n_results, count)
    )

    frames = []
    if results["metadatas"]:
        for meta, doc, distance in zip(
            results["metadatas"][0],
            results["documents"][0],
            results["distances"][0]
        ):
            frames.append({
                "frame_id": meta["frame_id"],
                "timestamp": meta["timestamp"],
                "location": meta["location"],
                "activity": meta["activity"],
                "security_level": meta["security_level"],
                "alert_reason": meta["alert_reason"],
                "relevance_score": round(1 - distance, 3)
            })
    return frames


def query_by_location(location: str) -> list:
    """Returns all frames from a specific location"""
    results = collection.get(
        where={"location": location}
    )
    return _format_get_results(results)


def query_by_security_level(level: str) -> list:
    """Returns all frames with a specific security level e.g. 'critical'"""
    results = collection.get(
        where={"security_level": level}
    )
    return _format_get_results(results)


def query_alerts_only() -> list:
    """Returns all frames that triggered alerts"""
    results = collection.get(
        where={"requires_alert": "True"}
    )
    return _format_get_results(results)


def get_frame_count() -> int:
    """Returns total number of indexed frames"""
    return collection.count()


def _format_get_results(results: dict) -> list:
    """Formats ChromaDB get() results into clean list"""
    frames = []
    if results["metadatas"]:
        for meta in results["metadatas"]:
            frames.append({
                "frame_id": meta["frame_id"],
                "timestamp": meta["timestamp"],
                "location": meta["location"],
                "activity": meta["activity"],
                "security_level": meta["security_level"],
                "alert_reason": meta["alert_reason"],
            })
    return frames


def clear_index() -> None:
    """Clears all indexed frames — use for fresh runs"""
    global collection
    client.delete_collection("drone_security_frames")
    collection = client.get_or_create_collection(
        name="drone_security_frames",
        metadata={"hnsw:space": "cosine"}
    )
    print("🗑️  Index cleared.")