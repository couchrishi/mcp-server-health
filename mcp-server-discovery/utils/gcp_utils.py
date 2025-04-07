import logging
import os
from google.cloud import secretmanager, storage
from google.api_core import exceptions as google_exceptions

logger = logging.getLogger(__name__)

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
