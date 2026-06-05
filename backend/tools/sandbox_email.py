"""邮件沙箱 — 测试邮箱白名单下的真实安全发送"""
import smtplib, os, sys, time
from collections import deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from threading import Lock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    SANDBOX_MODE,
    EMAIL_HOST,
    EMAIL_PORT,
    EMAIL_USER,
    EMAIL_PASSWORD,
    EMAIL_FROM,
    EMAIL_USE_TLS,
    EMAIL_ALLOWED_RECIPIENTS,
    EMAIL_ALLOWED_DOMAINS,
    EMAIL_MAX_PER_MINUTE,
    EMAIL_MAX_BODY_LENGTH,
)


class EmailSandbox:
    """邮件发送沙箱，默认仅允许测试邮箱白名单。"""

    def __init__(self):
        self.mode = SANDBOX_MODE
        self.log = []
        self._sent_window = deque()
        self._lock = Lock()

    def _log(self, event: str, **kwargs):
        entry = {"event": event, "mode": self.mode, **kwargs}
        self.log.append(entry)
        print(f"[EmailSandbox:{self.mode}] {event}", kwargs)

    def send(self, to: str, subject: str = "", body: str = "",
             cc: str = None, bcc: str = None, source_ip: str = None) -> dict:
        if not to or not to.strip():
            return self._result("error", to=to, summary="收件人地址不能为空", reason="missing_recipient")

        recipients = self._parse_recipients(to, cc, bcc)
        if not recipients:
            return self._result("error", to=to, summary="未解析到有效收件人", reason="invalid_recipient")

        if len((body or "").encode("utf-8")) > EMAIL_MAX_BODY_LENGTH:
            return self._result("blocked", to=to, summary="邮件正文超过长度限制", reason="body_too_large", severity=80)

        blocked = self._check_recipient_policy(recipients)
        if blocked:
            return self._result(
                "blocked",
                to=to,
                summary="收件人不在测试邮箱白名单内，已阻断",
                reason=blocked,
                severity=90,
                data={"recipients": recipients, "source_ip": source_ip},
            )

        if self._rate_limited():
            return self._result(
                "blocked",
                to=to,
                summary="邮件发送频率超限，已阻断",
                reason="rate_limited",
                severity=85,
                data={"limit_per_minute": EMAIL_MAX_PER_MINUTE},
            )

        if self.mode != "real":
            return self._result(
                "mock",
                to=to,
                summary="当前为 mock 模式，邮件未真实发送",
                reason="mock_mode",
                data={"recipients": recipients, "subject": subject},
                mode="mock",
            )

        if not self._smtp_configured():
            return self._result(
                "blocked",
                to=to,
                summary="SMTP 配置缺失，已阻止真实发送",
                reason="smtp_not_configured",
                severity=75,
            )

        self._log("send_attempt", to=to, subject=subject, source_ip=source_ip)
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = Header(subject, "utf-8") if subject else "(无主题)"
            msg["From"] = EMAIL_FROM
            msg["To"] = to
            if cc:
                msg["Cc"] = cc
            part = MIMEText(body or "(无正文)", "plain", "utf-8")
            msg.attach(part)

            with smtplib.SMTP(EMAIL_HOST, int(EMAIL_PORT), timeout=15) as server:
                if EMAIL_USE_TLS:
                    server.starttls()
                if EMAIL_USER and EMAIL_PASSWORD:
                    server.login(EMAIL_USER, EMAIL_PASSWORD)
                server.sendmail(EMAIL_FROM, recipients, msg.as_string())

            self._mark_sent()
            self._log("real_sent", to=to, subject=subject)
            return self._result(
                "executed",
                to=to,
                summary="测试邮箱白名单校验通过，邮件已真实发送",
                data={
                    "to": to,
                    "subject": subject,
                    "message_id": f"<real-{hash(to + str(hash(body)))}@{EMAIL_HOST}>",
                    "sent_at": self._now(),
                    "recipients": recipients,
                },
                severity=20,
            )
        except smtplib.SMTPAuthenticationError:
            return self._result("error", to=to, summary="SMTP认证失败", reason="smtp_auth_error", severity=65)
        except smtplib.SMTPConnectError as e:
            return self._result("error", to=to, summary=f"SMTP连接失败: {e}", reason="smtp_connect_error", severity=60)
        except Exception as e:
            return self._result("error", to=to, summary=f"发送失败: {e}", reason="send_error", severity=60)

    def _parse_recipients(self, to: str, cc: str = None, bcc: str = None):
        all_values = [to or "", cc or "", bcc or ""]
        recipients = []
        for raw in all_values:
            for item in raw.replace(",", ";").split(";"):
                addr = item.strip().lower()
                if addr:
                    recipients.append(addr)
        return recipients

    def _check_recipient_policy(self, recipients):
        allowed_recipients = {r.lower() for r in EMAIL_ALLOWED_RECIPIENTS}
        allowed_domains = {d.lower() for d in EMAIL_ALLOWED_DOMAINS}
        for addr in recipients:
            if addr in allowed_recipients:
                continue
            domain = addr.split("@")[-1] if "@" in addr else ""
            if domain and domain in allowed_domains:
                continue
            return f"recipient_not_allowed:{addr}"
        return None

    def _smtp_configured(self) -> bool:
        placeholders = {"smtp.example.com", "your@email.com", "your_password", "ishield@yourdomain.com"}
        return all([EMAIL_HOST, EMAIL_FROM]) and EMAIL_HOST not in placeholders and EMAIL_FROM not in placeholders

    def _rate_limited(self) -> bool:
        now = time.time()
        with self._lock:
            while self._sent_window and now - self._sent_window[0] > 60:
                self._sent_window.popleft()
            return len(self._sent_window) >= EMAIL_MAX_PER_MINUTE

    def _mark_sent(self):
        with self._lock:
            self._sent_window.append(time.time())

    def _result(self, status: str, to: str = "", summary: str = "", reason: str = None,
                data: dict = None, severity: int = 50, mode: str = None) -> dict:
        return {
            "status": status,
            "tool": "send_email",
            "mode": mode or ("real" if self.mode == "real" else "mock"),
            "summary": summary,
            "audit": {
                "target": to,
                "reason": reason,
                "severity": severity,
                "threat_level": "high" if status == "blocked" else "low",
            },
            "data": data or {"to": to},
        }

    def get_log(self) -> list:
        return list(self.log)

    def _now(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


_sandbox = None


def get_sandbox() -> EmailSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = EmailSandbox()
    return _sandbox
