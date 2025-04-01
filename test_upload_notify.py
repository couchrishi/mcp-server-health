"""
Test script for GCS upload and SendGrid email notification.

Uses functions and configuration from the main health check script
to test the final steps using existing output files.
"""

import os
import logging
import sys
import datetime

# --- Google Cloud Imports ---
try:
    from google.cloud import secretmanager
    from google.cloud import storage
    from google.api_core import exceptions as google_exceptions
    GOOGLE_CLOUD_AVAILABLE = True
except ImportError as e:
    print(f"ERROR: Required Google Cloud libraries not found: {e}")
    print("Install using: pip install google-cloud-secret-manager google-cloud-storage")
    GOOGLE_CLOUD_AVAILABLE = False
    sys.exit(1)

# --- SendGrid Import ---
try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail, Email, To, Content
    SENDGRID_AVAILABLE = True
except ImportError:
    print("ERROR: sendgrid library not found. Email notifications will be disabled.")
    print("Install using: pip install sendgrid")
    SENDGRID_AVAILABLE = False

# --- Configuration Import ---
try:
    import config
except ImportError:
    print("ERROR: config.py not found. Please ensure it exists in the same directory.")
    sys.exit(1)

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
# --- End Logging Setup ---


# --- Copied Functions from mcp_server_health_check.py ---

def get_secret(secret_version_id: str, secret_name_for_log: str) -> str | None:
    """Fetches a secret payload from Google Secret Manager."""
    if not secret_version_id or "your-project-id" in secret_version_id or "your-secret-name" in secret_version_id:
        logger.critical(f"Secret Manager ID for {secret_name_for_log} ('{secret_version_id}') appears to be a placeholder or is not configured correctly in config.py.")
        return None
    try:
        logger.info(f"Attempting to fetch {secret_name_for_log} from Secret Manager: {secret_version_id}")
        client = secretmanager.SecretManagerServiceClient()
        response = client.access_secret_version(name=secret_version_id)
        secret_payload = response.payload.data.decode("UTF-8")
        logger.info(f"Successfully fetched {secret_name_for_log} from Secret Manager.")
        return secret_payload
    except google_exceptions.NotFound:
         logger.critical(f"Secret version '{secret_version_id}' for {secret_name_for_log} not found.")
         return None
    except google_exceptions.PermissionDenied:
         logger.critical(f"Permission denied accessing secret version '{secret_version_id}' for {secret_name_for_log}. Ensure the service account has 'Secret Manager Secret Accessor' role.")
         return None
    except Exception as e:
        logger.critical(f"Failed to access secret version '{secret_version_id}' for {secret_name_for_log}: {e}", exc_info=True)
        return None

def upload_to_gcs(bucket_name: str, source_file_path: str, destination_blob_name: str) -> bool:
    """Uploads a file to the specified GCS bucket."""
    if not os.path.exists(source_file_path):
        logger.error(f"GCS Upload Error: Local file '{source_file_path}' not found.")
        return False
    try:
        storage_client = storage.Client()
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(destination_blob_name)

        logger.info(f"Uploading {source_file_path} to gs://{bucket_name}/{destination_blob_name}...")
        blob.upload_from_filename(source_file_path)
        logger.info(f"File gs://{bucket_name}/{destination_blob_name} uploaded successfully.")
        return True
    except google_exceptions.NotFound:
        logger.error(f"GCS Error: Bucket '{bucket_name}' not found.")
        return False
    except google_exceptions.Forbidden as e:
        logger.error(f"GCS Error: Permission denied uploading to gs://{bucket_name}/{destination_blob_name}. Ensure service account has Storage Object Creator/Admin role. Details: {e}")
        return False
    except Exception as e:
        logger.exception(f"An unexpected error occurred during GCS upload: {e}")
        return False

def send_completion_email(subject: str, body_html: str, recipients: list[str], sender: str, api_key: str) -> bool:
    """Sends a completion email using SendGrid."""
    if not SENDGRID_AVAILABLE:
        logger.warning("SendGrid library not available, cannot send email.")
        return False
    if not api_key: logger.warning("SendGrid API key missing. Skipping email."); return False
    if not sender or "your-verified-domain.com" in sender: logger.warning("SendGrid sender email not configured or is placeholder. Skipping email."); return False
    if not recipients or "recipient@example.com" in recipients[0]: logger.warning("SendGrid recipient emails not configured or are placeholders. Skipping email."); return False

    message = Mail(
        from_email=sender,
        to_emails=recipients,
        subject=subject,
        html_content=body_html
    )
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        logger.info(f"SendGrid email sent. Status Code: {response.status_code}")
        if response.status_code >= 300:
             logger.warning(f"SendGrid Response Body: {response.body}")
             logger.warning(f"SendGrid Response Headers: {response.headers}")
        return response.status_code < 300
    except Exception as e:
        logger.exception(f"Failed to send email via SendGrid: {e}")
        return False

# --- Main Test Logic ---
if __name__ == "__main__":
    logger.info("--- Starting GCS Upload and Email Notification Test ---")

    if not GOOGLE_CLOUD_AVAILABLE:
        logger.critical("Google Cloud libraries not available. Exiting.")
        sys.exit(1)

    # --- Get SendGrid Key ---
    sendgrid_api_key = get_secret(config.SENDGRID_API_KEY_SECRET_ID, "SendGrid API Key") if SENDGRID_AVAILABLE else None
    if SENDGRID_AVAILABLE and not sendgrid_api_key:
        logger.warning("Failed to retrieve SendGrid API key. Email notification will be skipped.")

    # --- Perform GCS Uploads ---
    logger.info("--- Testing GCS Uploads ---")
    gcs_discovery_uploaded = upload_to_gcs(
        config.GCS_BUCKET_NAME,
        config.DISCOVERY_OUTPUT_FILE,
        os.path.basename(config.DISCOVERY_OUTPUT_FILE)
    )
    gcs_analysis_uploaded = upload_to_gcs(
        config.GCS_BUCKET_NAME,
        config.ANALYSIS_OUTPUT_FILE,
        os.path.basename(config.ANALYSIS_OUTPUT_FILE)
    )

    # --- Send Test Email ---
    if sendgrid_api_key:
        logger.info("--- Testing Email Notification ---")
        test_status = "Success (Test)" if gcs_discovery_uploaded and gcs_analysis_uploaded else "Partial/Failure (Test)"
        subject = f"MCP Health Check TEST Notification: {test_status}"
        gcs_link_discovery = f"https://storage.googleapis.com/{config.GCS_BUCKET_NAME}/{os.path.basename(config.DISCOVERY_OUTPUT_FILE)}" if gcs_discovery_uploaded else "N/A"
        gcs_link_analysis = f"https://storage.googleapis.com/{config.GCS_BUCKET_NAME}/{os.path.basename(config.ANALYSIS_OUTPUT_FILE)}" if gcs_analysis_uploaded else "N/A"

        body = f"""
        <h2>MCP Health Check - TEST RUN</h2>
        <p>This is a test notification for the GCS upload and email functionality.</p>
        <p><strong>Test Time (UTC):</strong> {datetime.datetime.now(datetime.timezone.utc).isoformat()}</p>
        <hr>
        <p><strong>GCS Upload Status:</strong></p>
        <ul>
            <li>Discovery File ({os.path.basename(config.DISCOVERY_OUTPUT_FILE)}): {'Success' if gcs_discovery_uploaded else 'Failed'} (<a href="{gcs_link_discovery}">Link</a>)</li>
            <li>Analysis File ({os.path.basename(config.ANALYSIS_OUTPUT_FILE)}): {'Success' if gcs_analysis_uploaded else 'Failed'} (<a href="{gcs_link_analysis}">Link</a>)</li>
        </ul>
        """
        email_sent = send_completion_email(
            subject, body, config.EMAIL_RECIPIENTS, config.EMAIL_SENDER, sendgrid_api_key
        )
        if not email_sent:
            logger.warning("Failed to send test email.")
    else:
        logger.warning("Skipping test email notification due to missing SendGrid API key or configuration.")

    logger.info("--- Test Script Finished ---")