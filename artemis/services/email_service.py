"""SMTP email delivery — used for scheduled report delivery and test messages.

Configuration lives in settings (key/value): smtp_host, smtp_port,
smtp_username, smtp_password, smtp_from, smtp_security (none|starttls|ssl).
"""

import logging
import os
import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from artemis.services.auth_scan_service import get_setting

logger = logging.getLogger(__name__)


def smtp_config():
    return {
        'host': get_setting('smtp_host', '') or '',
        'port': int(get_setting('smtp_port', '587') or 587),
        'username': get_setting('smtp_username', '') or '',
        'password': get_setting('smtp_password', '') or '',
        'from': get_setting('smtp_from', '') or (get_setting('smtp_username', '') or ''),
        'security': (get_setting('smtp_security', 'starttls') or 'starttls').lower(),
    }


def is_configured():
    c = smtp_config()
    return bool(c['host'] and c['from'])


def send_email(recipients, subject, body_text, body_html=None, attachments=None):
    """Send one message. `attachments` is a list of (filename, bytes, mimetype).

    Raises on failure so callers can surface the reason.
    """
    c = smtp_config()
    if not c['host']:
        raise RuntimeError("SMTP is not configured (set smtp_host / smtp_from in Settings).")
    if isinstance(recipients, str):
        recipients = [recipients]
    recipients = [r for r in recipients if r]
    if not recipients:
        raise RuntimeError("No recipients.")

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = c['from']
    msg['To'] = ', '.join(recipients)
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain='artemis.local')
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype='html')

    for fname, data, mimetype in (attachments or []):
        maintype, _, subtype = (mimetype or 'application/octet-stream').partition('/')
        msg.add_attachment(data, maintype=maintype, subtype=subtype or 'octet-stream',
                           filename=fname)

    timeout = 30
    if c['security'] == 'ssl':
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(c['host'], c['port'], timeout=timeout, context=ctx) as s:
            _auth_and_send(s, c, msg, recipients)
    else:
        with smtplib.SMTP(c['host'], c['port'], timeout=timeout) as s:
            s.ehlo()
            if c['security'] == 'starttls':
                s.starttls(context=ssl.create_default_context())
                s.ehlo()
            _auth_and_send(s, c, msg, recipients)

    logger.info(f"Email '{subject}' sent to {len(recipients)} recipient(s) via {c['host']}")


def _auth_and_send(server, c, msg, recipients):
    if c['username'] and c['password']:
        server.login(c['username'], c['password'])
    server.send_message(msg, from_addr=c['from'], to_addrs=recipients)


def send_test_email(recipient):
    send_email(
        recipient,
        "Artemis SMTP test",
        "This is a test message from Artemis. Your SMTP settings are working.",
        body_html="<p>This is a test message from <strong>Artemis</strong>. "
                  "Your SMTP settings are working.</p>",
    )


def send_report_email(recipients, schedule_name, report_row):
    """Email a generated report as an attachment."""
    branding_name = get_setting('report_org_name', '') or 'Artemis'
    summary = {}
    try:
        import json
        summary = json.loads(report_row.summary_json) if report_row.summary_json else {}
    except Exception:
        pass
    sev = summary.get('by_severity', {})
    lines = [
        f"Scheduled report: {schedule_name}",
        f"Scope: {report_row.title}",
        "",
        f"Assets in scope : {summary.get('assets', '—')}",
        f"Affected hosts  : {summary.get('affected_hosts', '—')}",
        f"Critical / High : {sev.get('critical', 0)} / {sev.get('high', 0)}",
        f"Exploitable     : {summary.get('exploitable', 0)}",
        f"Risk score      : {summary.get('risk_score', '—')}",
        "",
        "The full report is attached.",
    ]
    html = (
        f"<h2>{schedule_name}</h2>"
        f"<p>{report_row.title}</p>"
        "<table style='border-collapse:collapse'>"
        f"<tr><td style='padding:2px 10px'>Assets in scope</td><td><b>{summary.get('assets', '—')}</b></td></tr>"
        f"<tr><td style='padding:2px 10px'>Affected hosts</td><td><b>{summary.get('affected_hosts', '—')}</b></td></tr>"
        "<tr><td style='padding:2px 10px'>Critical / High</td>"
        f"<td><b>{sev.get('critical', 0)} / {sev.get('high', 0)}</b></td></tr>"
        f"<tr><td style='padding:2px 10px'>Exploitable</td><td><b>{summary.get('exploitable', 0)}</b></td></tr>"
        f"<tr><td style='padding:2px 10px'>Risk score</td><td><b>{summary.get('risk_score', '—')}</b></td></tr>"
        "</table><p>The full report is attached.</p>"
    )

    with open(report_row.file_path, 'rb') as fh:
        data = fh.read()
    mimetype = 'application/pdf' if report_row.fmt == 'pdf' else 'text/html'
    fname = os.path.basename(report_row.file_path)

    send_email(recipients, f"[{branding_name}] {schedule_name}",
               "\n".join(lines), body_html=html,
               attachments=[(fname, data, mimetype)])
