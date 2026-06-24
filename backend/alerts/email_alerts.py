from __future__ import annotations

import hashlib
import smtplib
from email.message import EmailMessage
from typing import Any


def mail_alerts_enabled(
    smtp_host: str,
    smtp_user: str,
    smtp_password: str,
    alert_email_to: list[str],
) -> bool:
    return bool(
        smtp_host
        and smtp_user
        and smtp_password
        and alert_email_to
    )


def critical_alert_signature(
    repo_id: str,
    critical_findings: list[dict[str, Any]],
    hmac_sha256_hex,
) -> str:

    digest_source = "|".join(
        [
            repo_id,
            *sorted(
                finding["secret_hash"]
                for finding in critical_findings
                if finding.get("secret_hash")
            ),
        ]
    )

    return hmac_sha256_hex(
        digest_source
    )


def critical_alert_subject(
    owner: str,
    name: str,
    critical_count: int,
) -> str:

    return (
        f"[DarkShield] "
        f"{critical_count} critical finding(s) "
        f"in {owner}/{name}"
    )


def critical_alert_body(
    owner: str,
    name: str,
    repo_url: str,
    critical_findings: list[dict[str, Any]],
    ai_reasoning: str,
    total_count: int,
) -> str:

    lines = [
        "DarkShield critical alert",
        "",
        f"Repository: {owner}/{name}",
        f"Repository URL: {repo_url}",
        f"Total findings: {total_count}",
        f"Critical findings: {len(critical_findings)}",
        "",
        "Critical finding details:",
    ]

    for index, finding in enumerate(
        critical_findings[:10],
        start=1,
    ):
        lines.append(
            f"{index}. "
            f"{finding['secret_type']} | "
            f"{finding['file_path']}:"
            f"{finding['line_number']} | "
            f"{finding['snippet']}"
        )

    if len(critical_findings) > 10:

        lines.append(
            f"... and "
            f"{len(critical_findings)-10} "
            f"more critical finding(s)"
        )

    if ai_reasoning:

        lines.extend(
            [
                "",
                "AI summary:",
                ai_reasoning,
            ]
        )

    lines.extend(
        [
            "",
            "Immediate response:",
            "- Rotate exposed secrets",
            "- Revoke any public or shared credentials",
            "- Review commit history and remove hardcoded values",
        ]
    )

    return "\n".join(lines)


def build_critical_alert_message(
    owner: str,
    name: str,
    repo_url: str,
    critical_findings: list[dict[str, Any]],
    ai_reasoning: str,
    total_count: int,
    alert_email_from: str,
    smtp_user: str,
    alert_email_to: list[str],
) -> EmailMessage:

    from_address = (
        alert_email_from
        or smtp_user
        or "darkshield@localhost"
    )

    message = EmailMessage()

    message["Subject"] = (
        critical_alert_subject(
            owner,
            name,
            len(critical_findings),
        )
    )

    message["From"] = from_address

    message["To"] = ", ".join(
        alert_email_to
    )

    message.set_content(
        critical_alert_body(
            owner,
            name,
            repo_url,
            critical_findings,
            ai_reasoning,
            total_count,
        )
    )

    return message


def deliver_email(
    message: EmailMessage,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_ssl: bool,
    smtp_use_tls: bool,
    smtp_timeout: float,
) -> None:

    try:

        if smtp_use_ssl:

            with smtplib.SMTP_SSL(
                smtp_host,
                smtp_port,
                timeout=smtp_timeout,
            ) as smtp:

                if (
                    smtp_user
                    and smtp_password
                ):
                    smtp.login(
                        smtp_user,
                        smtp_password,
                    )

                smtp.send_message(
                    message
                )

            print(
                f"OK: Email sent successfully "
                f"to {message['To']}"
            )

            return

        with smtplib.SMTP(
            smtp_host,
            smtp_port,
            timeout=smtp_timeout,
        ) as smtp:

            if smtp_use_tls:
                smtp.starttls()

            if (
                smtp_user
                and smtp_password
            ):
                smtp.login(
                    smtp_user,
                    smtp_password,
                )

            smtp.send_message(
                message
            )

        print(
            f"OK: Email sent successfully "
            f"to {message['To']}"
        )

    except smtplib.SMTPAuthenticationError as e:

        print(
            f"ERROR: SMTP Authentication "
            f"Failed: {e}"
        )

        raise

    except smtplib.SMTPException as e:

        print(
            f"ERROR: SMTP Error: {e}"
        )

        raise

    except Exception as e:

        print(
            f"ERROR: Email delivery failed: {e}"
        )

        raise


def critical_alert_already_sent(
    client,
    repo_id: str,
    scan_signature: str,
) -> bool:

    response = (
        client.table(
            "critical_alert_notifications"
        )
        .select("id")
        .eq(
            "repo_id",
            repo_id,
        )
        .eq(
            "scan_signature",
            scan_signature,
        )
        .eq(
            "delivery_status",
            "sent",
        )
        .limit(1)
        .execute()
    )

    rows = (
        getattr(
            response,
            "data",
            [],
        )
        or []
    )

    return bool(rows)


def record_critical_alert(
    client,
    repo_id: str,
    scan_signature: str,
    critical_count: int,
    total_count: int,
    recipients: list[str],
    delivery_status: str,
    error_message: str | None = None,
) -> None:

    payload = {
        "repo_id":
            repo_id,

        "scan_signature":
            scan_signature,

        "critical_count":
            critical_count,

        "total_count":
            total_count,

        "recipients":
            recipients,

        "delivery_status":
            delivery_status,

        "error_message":
            error_message,
    }

    (
        client.table(
            "critical_alert_notifications"
        )
        .upsert(
            payload,
            on_conflict=
                "repo_id,scan_signature",
        )
        .execute()
    )


def send_critical_mail(
    *,
    client,
    repo_id: str,
    owner: str,
    name: str,
    repo_url: str,
    critical_findings: list[dict[str, Any]],
    ai_reasoning: str,
    total_count: int,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_password: str,
    smtp_use_ssl: bool,
    smtp_use_tls: bool,
    smtp_timeout: float,
    alert_email_from: str,
    alert_email_to: list[str],
    hmac_sha256_hex,
    debug_log,
) -> tuple[bool, str | None]:

    if not mail_alerts_enabled(
        smtp_host,
        smtp_user,
        smtp_password,
        alert_email_to,
    ):
        return (
            False,
            "Email alerts disabled",
        )

    if not critical_findings:
        return (
            False,
            "No critical findings",
        )

    scan_signature = (
        critical_alert_signature(
            repo_id,
            critical_findings,
            hmac_sha256_hex,
        )
    )

    if critical_alert_already_sent(
        client,
        repo_id,
        scan_signature,
    ):
        return (
            False,
            "Alert already sent",
        )

    try:

        message = (
            build_critical_alert_message(
                owner,
                name,
                repo_url,
                critical_findings,
                ai_reasoning,
                total_count,
                alert_email_from,
                smtp_user,
                alert_email_to,
            )
        )

        deliver_email(
            message,
            smtp_host,
            smtp_port,
            smtp_user,
            smtp_password,
            smtp_use_ssl,
            smtp_use_tls,
            smtp_timeout,
        )

        record_critical_alert(
            client,
            repo_id,
            scan_signature,
            len(critical_findings),
            total_count,
            alert_email_to,
            "sent",
        )

        return (
            True,
            None,
        )

    except Exception as exc:

        debug_log(
            f"ERROR: {exc}"
        )

        try:

            record_critical_alert(
                client,
                repo_id,
                scan_signature,
                len(critical_findings),
                total_count,
                alert_email_to,
                "failed",
                str(exc),
            )

        except Exception:
            pass

        return (
            False,
            str(exc),
        )