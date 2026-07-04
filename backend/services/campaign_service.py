"""红队活动编排服务"""
from typing import Dict, Any, List
from threading import Lock, Thread
from datetime import datetime, timezone
import uuid

from services.redteam_generator import generate_attack_variants
from services.detection import hybrid_detect
from services.events import add_event
from services.websocket import broadcast_event

_campaigns: Dict[str, Dict[str, Any]] = {}
_campaign_lock = Lock()


def create_campaign(seed_text: str, strategies: List[str], iterations: int, variants_per_iteration: int = 5) -> Dict[str, Any]:
    campaign_id = f"camp-{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()
    campaign = {
        "campaign_id": campaign_id,
        "seed_text": seed_text,
        "strategies": strategies or [],
        "iterations": max(1, iterations),
        "variants_per_iteration": max(1, variants_per_iteration),
        "status": "queued",
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "progress": 0,
        "total_variants": 0,
        "detected_variants": 0,
        "evasion_variants": 0,
        "results": [],
        "top_evasions": [],
    }
    with _campaign_lock:
        _campaigns[campaign_id] = campaign
    return campaign


def start_campaign(campaign_id: str):
    thread = Thread(target=_run_campaign, args=(campaign_id,), daemon=True)
    thread.start()


def get_campaign(campaign_id: str) -> Dict[str, Any]:
    with _campaign_lock:
        return dict(_campaigns.get(campaign_id) or {})


def list_campaigns() -> List[Dict[str, Any]]:
    with _campaign_lock:
        campaigns = list(_campaigns.values())
    return sorted(campaigns, key=lambda item: item.get("created_at", ""), reverse=True)


def _run_campaign(campaign_id: str):
    with _campaign_lock:
        campaign = _campaigns.get(campaign_id)
        if not campaign:
            return
        campaign["status"] = "running"
        campaign["started_at"] = datetime.now(timezone.utc).isoformat()

    add_event(
        event_type="红队活动",
        detail=f"活动={campaign_id}, 开始执行 {campaign['iterations']} 轮",
        status="已启动",
        action="redteam_campaign",
        tool_name="campaign_runner",
        target=campaign_id,
        category="redteam_campaign",
        threat_level="medium",
        confidence=30,
        chain_id=campaign_id,
        stage="campaign_started",
        metadata={
            "strategies": campaign.get("strategies", []),
            "seed_text": campaign.get("seed_text", "")[:200],
        },
    )

    total_steps = campaign["iterations"]
    all_results = []
    detected = 0

    for idx in range(total_steps):
        variants = generate_attack_variants(campaign["seed_text"], n=campaign["variants_per_iteration"], provider="local")
        if campaign["strategies"]:
            variants = [v for v in variants if v.get("strategy") in campaign["strategies"]] or variants

        iteration_results = []
        for variant in variants:
            text = variant.get("variant", "")
            hybrid_alert, hybrid_reason, hybrid_data = hybrid_detect(text)
            rule_data = hybrid_data.get("rule") or {}
            semantic_data = hybrid_data.get("semantic") or {}
            rule_alert = bool(rule_data.get("alert"))
            rule_hit = rule_data.get("hit")
            rule_conf = rule_data.get("confidence", 0)
            semantic_alert = bool(semantic_data.get("alert"))
            if hybrid_alert:
                detected += 1
            result = {
                "iteration": idx + 1,
                "variant": text,
                "strategy": variant.get("strategy", "unknown"),
                "threat_level": hybrid_data.get("threat_level", variant.get("threat_level", "unknown")),
                "rule_detected": rule_alert,
                "rule_hit": rule_hit,
                "rule_confidence": rule_conf,
                "semantic_detected": semantic_alert,
                "hybrid_detected": hybrid_alert,
                "hybrid_confidence": hybrid_data.get("combined", 0),
                "reason": hybrid_reason,
            }
            iteration_results.append(result)
            all_results.append(result)

        _update_campaign_progress(campaign_id, idx + 1, total_steps, all_results, detected)
        broadcast_event("campaign_progress", {
            "campaign_id": campaign_id,
            "progress": round((idx + 1) / max(total_steps, 1) * 100, 1),
            "iteration": idx + 1,
            "detected_variants": detected,
            "total_variants": len(all_results),
        })

    with _campaign_lock:
        campaign = _campaigns.get(campaign_id)
        if not campaign:
            return
        campaign["status"] = "completed"
        campaign["completed_at"] = datetime.now(timezone.utc).isoformat()
        campaign["results"] = all_results
        campaign["total_variants"] = len(all_results)
        campaign["detected_variants"] = detected
        campaign["evasion_variants"] = max(0, len(all_results) - detected)
        campaign["progress"] = 100
        campaign["top_evasions"] = [
            item for item in sorted(all_results, key=lambda row: row.get("hybrid_confidence", 0))
            if not item.get("hybrid_detected")
        ][:5]

    add_event(
        event_type="红队活动",
        detail=f"活动={campaign_id}, 已完成, 检出率={_detection_rate(detected, len(all_results))}%",
        status="已完成",
        action="redteam_campaign",
        tool_name="campaign_runner",
        target=campaign_id,
        category="redteam_campaign",
        threat_level="high" if detected < len(all_results) else "medium",
        confidence=int(_detection_rate(detected, len(all_results))),
        chain_id=campaign_id,
        stage="campaign_completed",
        metadata={
            "detected_variants": detected,
            "total_variants": len(all_results),
            "top_evasions": _campaigns[campaign_id].get("top_evasions", []),
        },
    )


def _update_campaign_progress(campaign_id: str, completed_iterations: int, total_steps: int, results: List[Dict[str, Any]], detected: int):
    with _campaign_lock:
        campaign = _campaigns.get(campaign_id)
        if not campaign:
            return
        campaign["progress"] = round(completed_iterations / max(total_steps, 1) * 100, 1)
        campaign["results"] = list(results)
        campaign["total_variants"] = len(results)
        campaign["detected_variants"] = detected
        campaign["evasion_variants"] = max(0, len(results) - detected)
        campaign["top_evasions"] = [
            item for item in sorted(results, key=lambda row: row.get("hybrid_confidence", 0))
            if not item.get("hybrid_detected")
        ][:5]


def _detection_rate(detected: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(detected / total * 100, 1)
