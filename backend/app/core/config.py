from functools import lru_cache
from typing import Annotated, Any

from pydantic.functional_validators import BeforeValidator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _empty_string_to_none(value: Any) -> Any:
    if isinstance(value, str) and value.strip() == "":
        return None
    return value


OptionalInt = Annotated[int | None, BeforeValidator(_empty_string_to_none)]


class Settings(BaseSettings):
    api_prefix: str = "/api/v1"
    environment: str = "development"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-3-haiku-20240307"
    google_gemini_api_key: str | None = None
    google_gemini_model: str = "gemini-1.5-flash"
    ai_response_language: str = "en"
    mongo_url: str = "mongodb://mongo:27017"
    mongo_db: str = "hecate"
    mongo_vulnerabilities_collection: str = "vulnerabilities"
    mongo_cpe_collection: str = "cpe_catalog"
    mongo_asset_vendors_collection: str = "asset_vendors"
    mongo_asset_products_collection: str = "asset_products"
    mongo_asset_versions_collection: str = "asset_versions"
    mongo_ingestion_state_collection: str = "ingestion_state"
    mongo_ingestion_log_collection: str = "ingestion_logs"
    mongo_kev_collection: str = "known_exploited_vulnerabilities"
    mongo_saved_searches_collection: str = "saved_searches"
    opensearch_url: str = "http://opensearch:9200"
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_index: str = "hecate-vulnerabilities"
    opensearch_index_total_fields_limit: int = 2000

    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    euvd_timeout_seconds: int = 30
    euvd_page_size: int = 250
    euvd_rate_limit_seconds: float = 1.0
    euvd_max_records_per_run: OptionalInt = None
    vulnerability_initial_backfill_since: str | None = None

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json"
    nvd_api_key: str | None = None
    nvd_rate_limit_seconds: float = 6.0
    nvd_page_size: int = 2000

    cpe_base_url: str = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    cpe_max_records_per_run: OptionalInt = 10000

    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    ingestion_user_agent: str = "hecate-ingestion/0.1"
    ingestion_running_timeout_minutes: int = 60
    ingestion_bootstrap_on_startup: bool = True

    scheduler_enabled: bool = True
    scheduler_timezone: str = "UTC"
    scheduler_euvd_interval_minutes: int = 60
    scheduler_cpe_interval_hours: int = 24
    scheduler_nvd_interval_hours: int = 24
    scheduler_kev_interval_minutes: int = 60

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
