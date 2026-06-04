"""邮件沙箱 — Mock + 真实SMTP双模式"""
import smtplib, json, os, sys
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import SANDBOX_MODE, EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASSWORD, EMAIL_FROM, EMAIL_USE_TLS


class EmailSandbox:
    """邮件发送沙箱，支持Mock模式和真实SMTP模式"""

    def __init__(self):
        self.mode = SANDBOX_MODE
        self.log = []

    def _log(self, event: str, **kwargs):
        entry = {"event": event, "mode": self.mode, **kwargs}
        self.log.append(entry)
        print(f"[EmailSandbox:{self.mode}] {event}", kwargs)

    def send(self, to: str, subject: str = "", body: str = "",
             cc: str = None, bcc: str = None) -> dict:
        """
        发送邮件。

        Mock模式：记录日志，返回模拟响应，不真实发送。
        Real模式：真实通过SMTP发送（需正确配置 config.py）。

        参数:
            to:      收件人（支持逗号分隔多地址）
            subject: 邮件主题
            body:    邮件正文
            cc:      抄送（可选）
            bcc:     密送（可选）

        返回:
            {"status": "sent"|"mock_sent"|"error", "to": str, "message_id": str}
        """
        if not to or not to.strip():
            return {"status": "error", "message": "收件人地址不能为空"}

        to = to.strip()
        self._log("send_attempt", to=to, subject=subject)

        if self.mode == "mock":
            self._log("mock_sent", to=to, subject=subject)
            return {
                "status": "mock_sent",
                "to": to,
                "subject": subject,
                "message_id": f"<mock-{hash(to)}@ishield.local>",
                "mode": "mock",
                "note": "Mock模式：邮件未真实发送，仅作记录"
            }

        # Real模式
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = Header(subject, "utf-8") if subject else "(无主题)"
            msg["From"] = EMAIL_FROM
            msg["To"] = to
            if cc:
                msg["Cc"] = cc
            recipients = [r.strip() for r in to.replace(",", ";").split(";") if r.strip()]
            if cc:
                recipients += [r.strip() for r in cc.replace(",", ";").split(";") if r.strip()]

            part = MIMEText(body or "(无正文)", "plain", "utf-8")
            msg.attach(part)

            with smtplib.SMTP(EMAIL_HOST, int(EMAIL_PORT), timeout=15) as server:
                if EMAIL_USE_TLS:
                    server.starttls()
                if EMAIL_USER and EMAIL_PASSWORD:
                    server.login(EMAIL_USER, EMAIL_PASSWORD)
                server.sendmail(EMAIL_FROM, recipients, msg.as_string())

            self._log("real_sent", to=to, subject=subject)
            return {
                "status": "sent",
                "to": to,
                "subject": subject,
                "message_id": f"<real-{hash(to + str(hash(body)))}@{EMAIL_HOST}>",
                "mode": "real",
                "sent_at": self._now(),
            }
        except smtplib.SMTPConnectError as e:
            self._log("smtp_connect_error", to=to, error=str(e))
            return {"status": "error", "message": f"SMTP连接失败: {e}", "mode": "real"}
        except smtplib.SMTPAuthenticationError:
            self._log("smtp_auth_error", to=to)
            return {"status": "error", "message": "SMTP认证失败，请检查 EMAIL_USER/EMAIL_PASSWORD 配置", "mode": "real"}
        except Exception as e:
            self._log("send_error", to=to, error=str(e))
            return {"status": "error", "message": f"发送失败: {e}", "mode": "real"}

    def send_phishing_test(self, to: str, test_body: str = "") -> dict:
        """发送钓鱼测试邮件（演示用）"""
        phishing_subject = "=?utf-8?b?5aSn5rC4556h6LSn5L+h5oCN6LSn5L+h6LSn6KGM5bCK6bKq?= [IT Security Test]"
        phishing_body = test_body or (
            "【安全测试邮件】\n\n"
            "这是一封由IShield安全系统发送的钓鱼邮件测试。\n"
            "如果您收到此邮件，说明IShield的邮件沙箱检测功能正常工作。\n"
            "如有任何疑问请联系安全团队。"
        )
        return self.send(to, phishing_subject, phishing_body)

    def get_log(self) -> list:
        return list(self.log)

    def _now(self) -> str:
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── 全局单例 ────────────────────────────────────────────────────────────────
_sandbox = None

def get_sandbox() -> EmailSandbox:
    global _sandbox
    if _sandbox is None:
        _sandbox = EmailSandbox()
    return _sandbox
