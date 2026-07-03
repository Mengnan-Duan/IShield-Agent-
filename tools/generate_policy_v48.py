import json
from pathlib import Path

SURFACES = {
    "prompt_injection": "提示注入",
    "jailbreak": "模型越狱",
    "tool_hijacking": "工具调用劫持",
    "file_access": "文件访问越权",
    "data_exfiltration": "数据泄露外发",
    "api_ssrf": "API / SSRF",
    "rag_injection": "RAG 污染",
    "memory_poisoning": "记忆污染",
    "environment_pollution": "环境感知污染",
    "agent_delegation": "跨 Agent 委托越权",
    "code_execution": "代码执行风险",
    "database_abuse": "数据库滥用",
    "social_engineering": "社会工程",
    "compliance": "合规审计",
}


def make_rule(rid, name, category, tool, pattern, keywords, action="block",
              severity=80, scope="tool_call", tags=None):
    attack_surface = SURFACES.get(category, "运行时工具调用")
    if action == "confirm":
        response = f"进入确认队列，要求补充业务目的、审批人和执行后审计；重点核对{attack_surface}风险。"
    elif action == "log":
        response = f"保留审计记录并观察同源 Agent、Token 和 IP 的后续行为；用于{attack_surface}趋势分析。"
    else:
        response = f"保持阻断并写入事件中心，将样本加入回归集；同步检查同源主体是否继续触发{attack_surface}规则。"

    sample = keywords[0] if keywords else pattern
    first_tool = tool.split("|")[0]
    if first_tool in {"read_file", "write_file"}:
        params = f"path={sample}"
    elif first_tool == "query_db":
        params = f"query={sample}"
    elif first_tool == "send_email":
        params = f"to=user@example.com&content={sample}"
    elif first_tool in {"http_request", "call_api"}:
        params = f"url={sample}"
    elif first_tool in {"run_code", "shell"}:
        params = f"code={sample}"
    else:
        params = f"input={sample}"

    return {
        "id": rid,
        "name": name,
        "tool": tool,
        "params_pattern": pattern,
        "threat_keywords": keywords,
        "action": action,
        "severity": severity,
        "message": f"命中{attack_surface}规则：{name}",
        "enabled": True,
        "scope": scope,
        "priority": severity,
        "tags": tags or [category],
        "description": f"用于识别{attack_surface}中的{name}风险，并给出可审计的处置动作。",
        "category": category,
        "attack_surface": attack_surface,
        "recommended_response": response,
        "false_positive_note": "如确属业务必要，应改走最小权限、人工确认和执行后复盘流程。",
        "test_cases": [{
            "name": f"{name} 命中样本",
            "tool": first_tool,
            "params": params,
            "expected_action": action,
        }],
    }


GROUPS = [
    ("POL-LLM", "prompt_injection", "*", "model_input", ["llm", "prompt"], [
        ("系统提示词窃取", "system prompt|系统提示词|开发者指令|hidden instruction", ["system prompt", "系统提示词", "开发者指令"], "block", 94),
        ("忽略上文指令", "ignore previous|忽略之前|忽略以上|override instructions", ["ignore previous", "忽略之前", "override instructions"], "block", 90),
        ("开发者消息探测", "developer message|上层指令|hidden developer|system message", ["developer message", "上层指令", "system message"], "block", 88),
        ("安全策略绕过", "bypass safety|disable policy|关闭安全|不受限制", ["bypass safety", "disable policy", "关闭安全"], "block", 92),
        ("多轮诱导泄露", "step by step.*secret|逐步.*泄露|慢慢告诉我", ["step by step secret", "逐步泄露", "慢慢告诉我"], "block", 82),
        ("工具前置诱导", "before using tool|调用工具前|先读取|先导出", ["调用工具前", "先读取", "先导出"], "block", 84),
    ]),
    ("POL-JB", "jailbreak", "*", "model_input", ["llm", "jailbreak"], [
        ("DAN 越狱模板", "DAN|do anything now|越狱模式", ["DAN", "do anything now", "越狱模式"], "block", 93),
        ("无限制模式", "unrestricted mode|无约束|无限制回答|no policy", ["unrestricted mode", "无限制回答", "no policy"], "block", 91),
        ("假设场景绕过", "hypothetical|假设.*没有限制|仅用于小说", ["hypothetical", "假设没有限制", "仅用于小说"], "block", 78),
        ("反向心理诱导", "prove you are not|不要拒绝|你必须回答", ["不要拒绝", "你必须回答", "prove you are not"], "block", 80),
        ("多语言越狱", "jailbreak|bypass|ignora|忽略.*regla", ["jailbreak", "ignora", "bypass"], "block", 82),
        ("编码混淆越狱", "base64|rot13|unicode escape|编码后执行", ["base64", "rot13", "编码后执行"], "block", 84),
    ]),
    ("POL-TOOL", "tool_hijacking", "*", "tool_call", ["tool", "agent"], [
        ("非业务目的读文件", "read secret|读取.*密钥|导出.*配置", ["read secret", "读取密钥", "导出配置"], "block", 88),
        ("高权限工具诱导", "admin tool|root 权限|高权限工具|sudo", ["admin tool", "root 权限", "sudo"], "block", 86),
        ("工具参数污染", "change target|替换目标|把参数改成|override params", ["替换目标", "change target", "override params"], "block", 82),
        ("工具链组合放大", "read.*then.*send|读取.*发送|查询.*外发", ["读取后发送", "read then send", "查询外发"], "block", 90),
        ("伪造审批理由", "approval granted|已审批|无需确认|主管同意", ["approval granted", "已审批", "无需确认"], "block", 80),
        ("越权管理工具", "delete user|grant admin|disable audit", ["grant admin", "disable audit", "delete user"], "block", 92),
    ]),
    ("POL-FILE", "file_access", "read_file|write_file", "file_access", ["file", "credential"], [
        ("路径遍历", r"\.\./|\.\.\\|%2e%2e", ["../", "..\\", "%2e%2e"], "block", 92),
        ("系统敏感路径", r"/etc/passwd|/etc/shadow|windows/system32", ["/etc/passwd", "/etc/shadow", "system32"], "block", 96),
        ("环境变量文件读取", r"\.env|env.local|config\.secret", [".env", "env.local", "config.secret"], "block", 94),
        ("SSH 密钥读取", r"id_rsa|id_ed25519|authorized_keys|\.ssh", ["id_rsa", ".ssh", "authorized_keys"], "block", 95),
        ("批量文件枚举", "glob\\(|recursive|list all|枚举文件", ["recursive", "list all", "枚举文件"], "block", 78),
        ("覆盖安全配置", "disable_security|allow_all|set policy off", ["disable_security", "allow_all", "policy off"], "block", 91),
    ]),
    ("POL-EXFIL", "data_exfiltration", "send_email|post_social|http_request|call_api|query_db", "external_egress", ["egress", "credential"], [
        ("API Key 外发", "api_key|apikey|access_key|sk-[a-zA-Z0-9]", ["api_key", "apikey", "sk-"], "block", 96),
        ("Token 外发", "bearer token|refresh_token|jwt|authorization:", ["bearer token", "refresh_token", "jwt"], "block", 95),
        ("Cookie 外发", "cookie|sessionid|csrf|set-cookie", ["cookie", "sessionid", "csrf"], "block", 88),
        ("用户隐私批量外发", "身份证|手机号|email.*导出|privacy", ["身份证", "手机号", "privacy"], "block", 90),
        ("数据库导出", "dump database|export users|select.*password", ["dump database", "export users", "select password"], "block", 92),
        ("附件携敏外发", "attach.*secret|附件.*密钥|send.*credential", ["附件密钥", "send credential", "attach secret"], "block", 88),
    ]),
    ("POL-API", "api_ssrf", "http_request|call_api", "external_egress", ["api", "ssrf"], [
        ("访问 metadata 服务", r"169\.254\.169\.254|metadata.google.internal|instance-data", ["169.254.169.254", "metadata.google.internal"], "block", 96),
        ("访问 localhost", r"localhost|127\.0\.0\.1|0\.0\.0\.0", ["localhost", "127.0.0.1"], "confirm", 86),
        ("访问私有网段", r"10\.|172\.16\.|192\.168\.|intranet", ["10.", "192.168.", "intranet"], "confirm", 84),
        ("Debug 接口探测", "/debug|/admin|/actuator|/internal", ["/debug", "/admin", "/internal"], "confirm", 86),
        ("回调地址污染", "callback=.*http|redirect_uri=.*http|webhook=.*evil", ["callback=http", "redirect_uri", "webhook=evil"], "confirm", 82),
        ("携凭证访问外域", "authorization=.*http|token=.*https|api_key=.*http", ["authorization=http", "token=https", "api_key=http"], "block", 90),
    ]),
    ("POL-RAG", "rag_injection", "rag_search|retrieve|*", "model_input", ["rag", "prompt"], [
        ("文档内嵌忽略指令", "RAGDOC_IGNORE_DIRECTIVE|ignore previous|忽略系统|以上规则无效", ["RAGDOC_IGNORE_DIRECTIVE", "ignore previous", "忽略系统"], "block", 88),
        ("检索内容要求泄露系统提示", "RAGDOC_SHOW_HIDDEN|reveal system prompt|输出系统提示|show hidden", ["RAGDOC_SHOW_HIDDEN", "reveal system prompt", "输出系统提示"], "block", 90),
        ("文档要求调用工具", "call tool|调用 read_file|发送邮件", ["call tool", "调用 read_file", "发送邮件"], "block", 84),
        ("外部链接诱导", "open this link|点击链接|访问外部", ["open this link", "点击链接", "访问外部"], "confirm", 78),
        ("伪造权威来源", "official policy says|官方要求|安全团队要求", ["official policy says", "官方要求", "安全团队要求"], "confirm", 76),
    ]),
    ("POL-MEM", "memory_poisoning", "memory_write|conversation|*", "memory", ["memory", "agent"], [
        ("写入长期恶意偏好", "remember.*ignore|记住.*不要拦截|以后都放行", ["remember ignore", "以后都放行", "不要拦截"], "block", 90),
        ("修改用户身份设定", "remember I am admin|我是管理员|永久授权", ["remember I am admin", "我是管理员", "永久授权"], "block", 86),
        ("注入虚假安全例外", "security exception|安全例外|白名单用户", ["security exception", "安全例外", "白名单用户"], "block", 84),
        ("要求记住密钥", "remember.*token|保存密钥|记住密码", ["remember token", "保存密钥", "记住密码"], "block", 88),
        ("污染 Agent 角色边界", "from now on you are admin|以后你是管理员", ["from now on you are admin", "以后你是管理员"], "block", 86),
    ]),
    ("POL-ENV", "environment_pollution", "*", "runtime_context", ["context", "environment"], [
        ("伪造环境变量", "ISHIELD_ALLOW_ALL|DISABLE_GUARD|SAFE_MODE=false", ["ISHIELD_ALLOW_ALL", "DISABLE_GUARD", "SAFE_MODE=false"], "confirm", 88),
        ("污染工作目录", "change cwd|切换目录到|workspace override", ["change cwd", "切换目录", "workspace override"], "confirm", 78),
        ("伪造系统时间", "set date|修改时间|time travel", ["set date", "修改时间", "time travel"], "confirm", 72),
        ("污染上下文来源", "source is trusted|来源可信|internal user", ["source is trusted", "来源可信", "internal user"], "confirm", 80),
    ]),
    ("POL-AGENT", "agent_delegation", "agent_delegate|agent_message|*", "agent_cluster", ["agent", "delegation"], [
        ("低权限委托高权限工具", "delegate.*admin|让管理员Agent|高权限Agent", ["delegate admin", "管理员Agent", "高权限Agent"], "block", 90),
        ("伪造 Agent 角色", "agent_role=admin|我是Admin Agent|role override", ["agent_role=admin", "Admin Agent", "role override"], "block", 88),
        ("跨 Agent 上下文污染", "forward this instruction|转发给.*Agent|共享隐藏指令", ["forward this instruction", "转发给Agent", "共享隐藏指令"], "block", 84),
        ("多 Agent 工具链放大", "planner.*tool.*mail|researcher.*admin|多工具组合", ["planner tool mail", "researcher admin", "多工具组合"], "block", 86),
    ]),
    ("POL-CODE", "code_execution", "run_code|execute_code|shell", "code_execution", ["code", "sandbox"], [
        ("执行 shell 命令", r"subprocess|os\.system|powershell|cmd.exe|bash", ["subprocess", "os.system", "powershell"], "block", 94),
        ("下载并执行远程脚本", r"curl .*\|.*sh|wget .*\|.*bash|iex\(", ["curl | sh", "wget | bash", "iex("], "block", 96),
        ("删除敏感文件", "rm -rf|del /s|Remove-Item.*Recurse", ["rm -rf", "Remove-Item", "del /s"], "block", 95),
        ("反弹连接", "reverse shell|nc .* -e|bash -i", ["reverse shell", "nc -e", "bash -i"], "block", 97),
        ("写入计划任务", "crontab|schtasks|startup folder", ["crontab", "schtasks", "startup folder"], "block", 88),
        ("混淆脚本执行", r"base64 -d|frombase64string|eval\(", ["base64 -d", "frombase64string", "eval("], "block", 86),
    ]),
    ("POL-DB", "database_abuse", "query_db", "data_query", ["sql", "database"], [
        ("危险表操作", "drop|delete|truncate|alter", ["drop table", "delete from", "truncate"], "block", 92),
        ("SQL 注入模式", "union select|or 1=1|--|;.*drop", ["union select", "or 1=1", "'; --"], "block", 95),
        ("密码字段查询", "password|passwd|pwd|secret|api_key|token", ["password", "passwd", "api_key"], "confirm", 70),
        ("管理员账户查询", "admin|root|administrator", ["admin", "root", "administrator"], "confirm", 72),
        ("批量导出用户", "select \\* from users|export users|dump", ["select * from users", "export users", "dump"], "block", 86),
    ]),
    ("POL-SOC", "social_engineering", "send_email|post_social", "external_egress", ["email", "compliance"], [
        ("钓鱼邮件拦截", "evil|steal|hack|钓鱼|fake|phish", ["evil", "steal", "钓鱼"], "block", 92),
        ("账户异常诱导", "账户异常|立即验证|点击链接|紧急", ["账户异常", "立即验证", "点击链接"], "confirm", 70),
        ("中奖诈骗诱导", "恭喜|中奖|领取奖励|gift card", ["恭喜", "中奖", "gift card"], "confirm", 68),
        ("合规敏感信息外发", "身份证|银行卡|手机号|住址", ["银行卡", "身份证", "手机号"], "confirm", 82),
    ]),
]


def build_rules():
    rules = []
    for prefix, category, tool, scope, tags, specs in GROUPS:
        for index, (name, pattern, keywords, action, severity) in enumerate(specs, 1):
            rules.append(make_rule(
                f"{prefix}-{index:03d}",
                name,
                category,
                tool,
                pattern,
                keywords,
                action,
                severity,
                scope,
                tags,
            ))
    return rules


if __name__ == "__main__":
    payload = {"version": "4.8", "rules": build_rules()}
    Path("backend/policies/default_policy.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(len(payload["rules"]))
