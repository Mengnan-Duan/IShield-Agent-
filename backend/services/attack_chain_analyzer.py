"""攻击链关联分析 — 从事件日志聚合同 chain_id 的操作，识别多阶段攻击模式，对应《实施意见》第7/10条"""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.events import get_events_from_db, get_chain_events
from typing import Dict, List, Any, Tuple


# ── 攻击阶段定义 ──────────────────────────────────────────────────────────────
STAGE_SEQUENCE = ["reconnaissance", "weaponization", "delivery", "exploitation", "persistence", "command_control", "exfiltration", "impact"]

# 端点 -> 攻击阶段映射
ENDPOINT_STAGE_MAP = {
    "/api/behavior": "reconnaissance",
    "/api/behavior/ip": "reconnaissance",
    "/api/policies": "reconnaissance",
    "/api/policies/evaluate": "reconnaissance",
    "/api/events": "reconnaissance",
    "/api/stats": "reconnaissance",
    "/api/samples": "reconnaissance",
    "/api/detect": "exploitation",
    "/api/simulate": "weaponization",
    "/api/redteam": "weaponization",
    "/api/campaigns": "weaponization",
    "/api/batch": "exploitation",
    "/api/compliance": "weaponization",
    "/api/conversation": "exploitation",
    "/api/simulate/email": "delivery",
    "/api/simulate/file": "delivery",
    "/api/simulate/http": "delivery",
    "/api/simulate/db": "delivery",
}

# 关键词 -> 攻击类型
KEYWORD_PATTERNS = {
    "injection": ["注入", "injection", "ignore", "forget", "bypass", "override"],
    "credential_access": ["password", "secret", "key", "token", "credential", "密码", "密钥"],
    "data_theft": ["extract", "dump", "export", "steal", "外泄", "窃取"],
    "system_tampering": ["delete", "drop", "truncate", "modify", "删除", "篡改"],
}


def classify_endpoint_stage(endpoint: str, detail: str = "") -> str:
    """根据端点和详情判断攻击阶段"""
    for path, stage in ENDPOINT_STAGE_MAP.items():
        if endpoint.startswith(path):
            return stage
    # 内容关键词二次判断
    text = (endpoint + " " + detail).lower()
    if any(k in text for k in KEYWORD_PATTERNS["credential_access"]):
        return "exfiltration"
    if any(k in text for k in KEYWORD_PATTERNS["data_theft"]):
        return "exfiltration"
    if any(k in text for k in KEYWORD_PATTERNS["system_tampering"]):
        return "impact"
    return "unknown"


def classify_attack_pattern(events: List[dict]) -> Dict[str, Any]:
    """
    根据链内事件分析攻击模式。
    """
    if not events:
        return {"pattern": "none", "stages": [], "confidence": 0}

    stages_found = set()
    threat_level = "none"
    max_confidence = 0

    for event in events:
        path = event.get("path", event.get("action", ""))
        detail = event.get("detail", "")
        stage = classify_endpoint_stage(path, detail)
        stages_found.add(stage)
        conf = event.get("confidence", 0) or 0
        max_confidence = max(max_confidence, conf)

        level = event.get("threat_level", "none")
        if level in ("critical", "high") or threat_level == "none":
            threat_level = level

    # 识别攻击模式
    stage_list = sorted(stages_found, key=lambda s: STAGE_SEQUENCE.index(s) if s in STAGE_SEQUENCE else 99)

    pattern = _identify_pattern(stage_list)

    return {
        "pattern": pattern,
        "stages": list(stage_list),
        "stage_count": len(stages_found),
        "threat_level": threat_level,
        "confidence": max_confidence,
        "is_multi_stage": len(stages_found) >= 2,
    }


def _identify_pattern(stages: List[str]) -> str:
    """根据阶段序列识别攻击模式"""
    has_recon = "reconnaissance" in stages
    has_weap = "weaponization" in stages
    has_exploit = "exploitation" in stages
    has_exfil = "exfiltration" in stages
    has_impact = "impact" in stages

    if has_recon and has_exfil:
        return "data_breach"          # 侦察 -> 数据外泄
    if has_recon and has_exploit:
        return "attack_injection"    # 侦察 -> 注入攻击
    if has_weap and has_exploit:
        return "weaponized_attack"    # 武器化攻击
    if has_exfil and has_impact:
        return "full_attack_chain"   # 完整攻击链
    if has_recon:
        return "reconnaissance"       # 纯侦察
    if has_exploit:
        return "exploitation_attempt" # 单一利用
    return "miscellaneous"


def detect_multi_stage_attack(chain_id: str) -> Dict[str, Any]:
    """
    检测链内的多阶段攻击。
    返回: {is_multi_stage, stages[], pattern, escalation_detected}
    """
    events = get_chain_events(chain_id)
    if not events:
        return {"is_multi_stage": False, "chain_id": chain_id}

    classification = classify_attack_pattern(events)
    stages = classification["stages"]

    # 检测权限升级路径：reconnaissance -> exploitation -> exfiltration
    escalation = "none"
    stage_order = [s for s in STAGE_SEQUENCE if s in stages]
    if len(stage_order) >= 2:
        escalation = "escalation_detected"

    return {
        "is_multi_stage": classification["is_multi_stage"],
        "chain_id": chain_id,
        "pattern": classification["pattern"],
        "stages": stages,
        "escalation": escalation,
        "threat_level": classification["threat_level"],
        "event_count": len(events),
        "confidence": classification["confidence"],
    }


def get_attack_chains_summary() -> Dict[str, Any]:
    """
    全局攻击链摘要。
    """
    # 从最近 1000 条事件中提取有 chain_id 的记录
    try:
        events = get_events_from_db(limit=1000)
    except Exception:
        events = []

    # 按 chain_id 分组
    chains: Dict[str, list] = {}
    for event in events:
        cid = event.get("chain_id")
        if cid and cid.startswith("attack-") or cid and cid.startswith("ct-") or cid and cid.startswith("conv-"):
            if cid not in chains:
                chains[cid] = []
            chains[cid].append(event)

    chain_summaries = []
    for cid, evts in chains.items():
        classification = classify_attack_pattern(evts)
        threat = classification["threat_level"]
        pattern = classification["pattern"]
        stages = classification["stages"]

        # 评分
        score = _chain_score(len(evts), len(stages), threat, classification["confidence"])

        chain_summaries.append({
            "chain_id": cid,
            "event_count": len(evts),
            "pattern": pattern,
            "stages": stages,
            "threat_level": threat,
            "score": score,
            "first_event": evts[0].get("timestamp") if evts else None,
            "last_event": evts[-1].get("timestamp") if evts else None,
            "is_multi_stage": classification["is_multi_stage"],
        })

    chain_summaries.sort(key=lambda x: x["score"], reverse=True)

    # 统计
    pattern_dist: Dict[str, int] = {}
    stage_dist: Dict[str, int] = {}
    for cs in chain_summaries:
        pattern_dist[cs["pattern"]] = pattern_dist.get(cs["pattern"], 0) + 1
        for stage in cs["stages"]:
            stage_dist[stage] = stage_dist.get(stage, 0) + 1

    return {
        "total_chains": len(chains),
        "multi_stage_count": sum(1 for c in chain_summaries if c["is_multi_stage"]),
        "top_chains": chain_summaries[:20],
        "pattern_distribution": pattern_dist,
        "stage_distribution": stage_dist,
    }


def _chain_score(event_count: int, stage_count: int, threat_level: str, confidence: int) -> int:
    score = 0
    score += min(event_count * 2, 30)
    score += stage_count * 15
    threat_scores = {"critical": 30, "high": 20, "medium": 10, "low": 5, "none": 0}
    score += threat_scores.get(threat_level, 0)
    score += min(confidence, 20)
    return min(score, 100)
