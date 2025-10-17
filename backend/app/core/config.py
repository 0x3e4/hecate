from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    api_prefix: str = "/api/v1"
    environment: str = "development"
    openai_api_key: str | None = None
    mongo_url: str = "mongodb://mongo:27017"
    mongo_db: str = "hecate"
    mongo_vulnerabilities_collection: str = "vulnerabilities"
    mongo_cpe_collection: str = "cpe_catalog"
    mongo_ingestion_state_collection: str = "ingestion_state"
    mongo_ingestion_log_collection: str = "ingestion_logs"
    opensearch_url: str = "http://opensearch:9200"
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_index: str = "hecate-vulnerabilities"

    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    euvd_timeout_seconds: int = 30
    euvd_page_size: int = 250
    euvd_rate_limit_seconds: float = 1.0
    euvd_initial_backfill_since: str | None = None

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json"
    nvd_api_key: str | None = None
    nvd_rate_limit_seconds: float = 6.0

    cpe_base_url: str = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    cpe_max_records_per_run: int | None = 10000

    ingestion_user_agent: str = "hecate-ingestion/0.1"

    scheduler_enabled: bool = True
    scheduler_timezone: str = "UTC"
    scheduler_euvd_interval_minutes: int = 60
    scheduler_cpe_interval_hours: int = 24

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
