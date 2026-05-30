"""
Cython fixture module for testing Cython compressed string table extraction.
Large enough to trigger LZSS as the default compression algorithm.
"""

# Module constants — identifiers, URLs, error messages
API_URL_STATUS = "https://api.example-internal.local/v2/agents/status"
API_URL_SUBMIT = "https://api.example-internal.local/v2/tasks/submit"
API_URL_CANCEL = "https://api.example-internal.local/v2/tasks/cancel"
API_URL_LIST = "https://api.example-internal.local/v2/agents/list"
API_URL_HEALTH = "https://api.example-internal.local/v2/health"
API_URL_METRICS = "https://api.example-internal.local/v2/metrics"

ENV_API_KEY = "EXAMPLE_API_KEY"
ENV_API_SECRET = "EXAMPLE_API_SECRET"
ENV_ENDPOINT = "EXAMPLE_API_ENDPOINT"
ENV_TIMEOUT = "EXAMPLE_REQUEST_TIMEOUT"
ENV_RETRY_COUNT = "EXAMPLE_RETRY_COUNT"
ENV_LOG_LEVEL = "EXAMPLE_LOG_LEVEL"

ERR_MISSING_KEY = "Missing required environment variable: EXAMPLE_API_KEY"
ERR_MISSING_SECRET = "Missing required environment variable: EXAMPLE_API_SECRET"
ERR_MISSING_ENDPOINT = "Missing required environment variable: EXAMPLE_API_ENDPOINT"
ERR_TIMEOUT = "Connection timed out after %d seconds for URL %s"
ERR_RETRY = "Retry attempt %d of %d for task %s failed with error: %s"
ERR_INVALID_TOKEN = "Invalid or expired token for client %s"
ERR_RATE_LIMIT = "Rate limit exceeded for endpoint %s, retry after %d seconds"
ERR_SERVER = "Server returned unexpected status %d for request to %s"
ERR_PARSE = "Failed to parse response from %s: %s"
ERR_AUTH = "Authentication failed for user %s: %s"
ERR_CONNECT = "Failed to connect to %s after %d retries"
ERR_CONFIG = "Invalid configuration: %s must be set to a non-empty string"
ERR_TYPE = "Expected %s but got %s for parameter %s"
ERR_MISSING = "Required parameter %s is missing from request"

MSG_INIT = "Initializing client session for endpoint %s"
MSG_CONNECTED = "Successfully connected to %s"
MSG_DISCONNECTED = "Disconnected from %s"
MSG_RETRY = "Retrying request to %s (attempt %d of %d)"
MSG_SUCCESS = "Request to %s completed successfully in %dms"
MSG_CACHE_HIT = "Cache hit for key %s"
MSG_CACHE_MISS = "Cache miss for key %s"
MSG_RELOAD = "Reloading configuration from environment"
MSG_SHUTDOWN = "Shutting down client gracefully"

MODULE_PATH_AGENT = "src/example_pkg/agent.py"
MODULE_PATH_SESSION = "src/example_pkg/session.py"
MODULE_PATH_TASKS = "src/example_pkg/tasks.py"
MODULE_PATH_AUTH = "src/example_pkg/auth.py"
MODULE_PATH_CONFIG = "src/example_pkg/config.py"
MODULE_PATH_UTILS = "src/example_pkg/utils.py"
MODULE_PATH_MODELS = "src/example_pkg/models.py"
MODULE_PATH_CLIENT = "src/example_pkg/client.py"

SUPPORTED_PROVIDERS = ["openai", "azure", "custom", "local", "mock"]
DEFAULT_MODEL = "gpt-4o"
DEFAULT_TIMEOUT = 30
DEFAULT_RETRY_COUNT = 3

def fetch_agent_response(url: str, token: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    """Fetch a response from the agent API."""
    if not token:
        raise ValueError(ERR_MISSING_KEY)
    if not url:
        raise ValueError(ERR_MISSING_ENDPOINT)
    return f"Response from {url}"

def initialize_client_session(api_key: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Initialize a client session with the given API key."""
    if not api_key:
        raise RuntimeError(ERR_MISSING_KEY)
    return {"api_key": api_key, "timeout": timeout, "url": API_URL_STATUS}

def validate_token_expiry(token: str) -> bool:
    """Check if the token has not expired."""
    return len(token) > 10

def rotate_api_credentials(old_key: str, new_key: str) -> bool:
    """Rotate API credentials atomically."""
    if not old_key or not new_key:
        raise ValueError(ERR_CONFIG % "api_key")
    return True

def dispatch_async_task(task_id: str, payload: dict) -> str:
    """Dispatch an asynchronous task to the agent."""
    if not task_id:
        raise ValueError(ERR_MISSING % "task_id")
    return f"Dispatched task {task_id}"
