import logging

# --- SendGrid Import ---
try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail, Email, To, Content
    SENDGRID_AVAILABLE = True
except ImportError:
    print("ERROR: sendgrid library not found. Email notifications will be disabled.")
    print("Install using: pip install sendgrid")
    SENDGRID_AVAILABLE = False

logger = logging.getLogger(__name__)

def send_completion_email(subject: str, body_html: str, recipients: list[str], sender: str, api_key: str) -> bool:
    """Sends a completion email using SendGrid."""
    if not SENDGRID_AVAILABLE: logger.warning("SendGrid library not available, cannot send email."); return False
    if not api_key: logger.warning("SendGrid API key missing. Skipping email."); return False
    if not sender or "your-verified-domain.com" in sender: logger.warning("SendGrid sender email not configured or is placeholder. Skipping email."); return False
    if not recipients or "recipient@example.com" in recipients[0]: logger.warning("SendGrid recipient emails not configured or are placeholders. Skipping email."); return False

    message = Mail(from_email=sender, to_emails=recipients, subject=subject, html_content=body_html)
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        logger.info(f"SendGrid email sent. Status Code: {response.status_code}")
        if response.status_code >= 300: logger.warning(f"SendGrid Response Body: {response.body}"); logger.warning(f"SendGrid Response Headers: {response.headers}")
        return response.status_code < 300
    except Exception as e:
        logger.exception(f"Failed to send email via SendGrid: {e}")
        return False