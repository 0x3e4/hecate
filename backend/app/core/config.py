from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    api_prefix: str = "/api"
    environment: str = "development"
    openai_api_key: str | None = None
    mongo_url: str = "mongodb://mongo:27017"
    mongo_db: str = "hecate"
    mongo_vulnerabilities_collection: str = "vulnerabilities"
    opensearch_url: str = "http://opensearch:9200"
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_index: str = "hecate-vulnerabilities"

    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    euvd_timeout_seconds: int = 30
    euvd_page_size: int = 250
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json"
    nvd_api_key: str | None = None
    ingestion_user_agent: str = "hecate-ingestion/0.1"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
