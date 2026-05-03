from functools import lru_cache
from typing import Annotated, Any

from pydantic import Field
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
    log_level: str = "INFO"
    openai_api_key: str | None = None
    openai_model: str = "gpt-4o-mini"
    openai_reasoning_effort: str = "medium"
    ai_max_output_tokens: int = 16000
    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-3-haiku-20240307"
    google_gemini_api_key: str | None = None
    google_gemini_model: str = "gemini-1.5-flash"
    openai_compatible_base_url: str | None = None
    openai_compatible_api_key: str | None = None
    openai_compatible_model: str = ""
    openai_compatible_label: str = "Local / OpenAI-Compatible"
    ai_response_language: str = "en"
    ai_web_search_enabled: bool = True
    ai_analysis_password: str | None = None
    system_password: str | None = None
    mongo_url: str = "mongodb://mongo:27017"
    mongo_username: str | None = None
    mongo_password: str | None = None
    mongo_tls: bool = False
    mongo_tls_cert_key_file: str | None = None
    mongo_db: str = "hecate"
    mongo_vulnerabilities_collection: str = "vulnerabilities"
    mongo_cpe_collection: str = "cpe_catalog"
    mongo_asset_vendors_collection: str = "asset_vendors"
    mongo_asset_products_collection: str = "asset_products"
    mongo_asset_versions_collection: str = "asset_versions"
    mongo_ingestion_state_collection: str = "ingestion_state"
    mongo_ingestion_log_collection: str = "ingestion_logs"
    mongo_kev_collection: str = "known_exploited_vulnerabilities"
    mongo_cwe_collection: str = "cwe_catalog"
    mongo_capec_collection: str = "capec_catalog"
    mongo_saved_searches_collection: str = "saved_searches"
    mongo_scan_targets_collection: str = "scan_targets"
    mongo_scans_collection: str = "scans"
    mongo_scan_findings_collection: str = "scan_findings"
    mongo_scan_sbom_collection: str = "scan_sbom_components"
    mongo_scan_layers_collection: str = "scan_layer_analysis"
    mongo_notification_rules_collection: str = "notification_rules"
    mongo_notification_channels_collection: str = "notification_channels"
    mongo_notification_templates_collection: str = "notification_templates"
    mongo_license_policies_collection: str = "license_policies"
    mongo_environment_inventory_collection: str = "environment_inventory"
    mongo_malware_intel_collection: str = "malware_intel"
    opensearch_url: str = "https://opensearch:9200"
    opensearch_username: str | None = None
    opensearch_password: str | None = None
    opensearch_index: str = "hecate-vulnerabilities"
    opensearch_index_total_fields_limit: int = 2000
    opensearch_index_max_result_window: int = 200000
    opensearch_verify_certs: bool = False
    opensearch_ca_cert: str | None = None

    http_ca_bundle: str | None = None

    euvd_base_url: str = "https://euvdservices.enisa.europa.eu/api"
    euvd_timeout_seconds: int = 30
    euvd_page_size: int = 250
    euvd_rate_limit_seconds: float = 1.0
    euvd_max_retries: int = 3
    euvd_retry_backoff_seconds: float = 5.0
    euvd_max_records_per_run: OptionalInt = None
    vulnerability_initial_backfill_since: str | None = None

    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json"
    nvd_api_key: str | None = None
    nvd_timeout_seconds: int = 60
    nvd_rate_limit_seconds: float = 6.0
    nvd_page_size: int = 2000
    nvd_max_retries: int = 5
    nvd_retry_backoff_seconds: float = 5.0
    nvd_max_records_per_run: OptionalInt = None

    cpe_base_url: str = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    cpe_max_records_per_run: OptionalInt = 10000

    kev_feed_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    cwe_base_url: str = "https://cwe-api.mitre.org/api/v1"
    cwe_timeout_seconds: int = 30
    cwe_rate_limit_seconds: float = 1.0

    capec_xml_url: str = "https://capec.mitre.org/data/xml/capec_latest.xml"
    capec_timeout_seconds: int = 60

    circl_base_url: str = "https://vulnerability.circl.lu/api"
    circl_timeout_seconds: int = 30
    circl_rate_limit_seconds: float = 1.0
    circl_max_retries: int = 3
    circl_retry_backoff_seconds: float = 3.0
    circl_max_records_per_run: OptionalInt = 1000

    ghsa_base_url: str = "https://api.github.com/advisories"
    ghsa_token: str | None = None
    ghsa_timeout_seconds: int = 30
    ghsa_rate_limit_seconds: float = 1.0
    ghsa_max_retries: int = 3
    ghsa_retry_backoff_seconds: float = 5.0
    ghsa_max_records_per_run: OptionalInt = 5000

    osv_base_url: str = "https://api.osv.dev/v1"
    osv_timeout_seconds: int = 30
    osv_rate_limit_seconds: float = 0.5
    osv_max_retries: int = 5
    osv_retry_backoff_seconds: float = 5.0
    # Per-run record cap for OSV incremental syncs. With the cursor logic in
    # OsvPipeline.sync (advance to max_processed_modified on cap-hit instead
    # of `now`), a cap is now safe — but None is the documented default
    # because the timeout (`INGESTION_RUNNING_TIMEOUT_MINUTES`) is the right
    # primary bound for runtime. Set a positive value only if you need to
    # throttle a noisy upstream window without raising the global timeout.
    osv_max_records_per_run: OptionalInt = None
    # Concurrency knobs for the OSV initial-sync per-record loop. The producer
    # buffers `osv_initial_sync_batch_size` records, then dispatches them via
    # `asyncio.gather` with a `Semaphore(osv_initial_sync_concurrency)` cap.
    # Bookkeeping (counters, cursor, progress) stays single-threaded on the
    # producer. Incremental sync is unaffected — it processes serially because
    # the OSV REST limiter (osv_rate_limit_seconds) makes parallelism marginal.
    osv_initial_sync_concurrency: int = 16
    osv_initial_sync_batch_size: int = 32

    # deps.dev enrichment — fills in actual published versions for MAL-* OSV
    # records that ship with the conservative `introduced: "0"` range (meaning
    # "all versions"). Runs inline during OSV ingest on new MAL-* entries and
    # via `poetry run python -m app.cli enrich-mal` for backfill. No API key.
    deps_dev_base_url: str = "https://api.deps.dev/v3"
    deps_dev_timeout_seconds: int = 15
    deps_dev_rate_limit_seconds: float = 0.1  # 10 req/s default
    deps_dev_max_retries: int = 3
    deps_dev_retry_backoff_seconds: float = 2.0

    ingestion_user_agent: str = "hecate-ingestion/1.0"
    ingestion_running_timeout_minutes: int = 60
    ingestion_bootstrap_on_startup: bool = True
    ingestion_priority_vuln_db: str = "NVD"  # NVD or EUVD

    scheduler_enabled: bool = True
    tz: str = "UTC"
    scheduler_timezone: str = "UTC"
    scheduler_euvd_interval_minutes: int = 60
    scheduler_cpe_interval_minutes: int = 1440
    scheduler_nvd_interval_minutes: int = 10
    scheduler_kev_interval_minutes: int = 60
    scheduler_cwe_interval_days: int = 7
    scheduler_capec_interval_days: int = 7
    scheduler_circl_interval_minutes: int = 120
    scheduler_ghsa_interval_minutes: int = 120
    scheduler_osv_interval_minutes: int = 120

    # Full sync scheduling (weekly verification runs)
    scheduler_euvd_full_sync_enabled: bool = True
    scheduler_euvd_full_sync_cron_hour: int = 2  # 2 AM UTC
    scheduler_euvd_full_sync_cron_day_of_week: str = "sun"  # Sunday
    scheduler_nvd_full_sync_enabled: bool = True
    scheduler_nvd_full_sync_cron_hour: int = 2  # 2 AM UTC
    scheduler_nvd_full_sync_cron_day_of_week: str = "wed"  # Wednesday
    # OSV initial-mode full sync re-pulls each ecosystem's all.zip, so it
    # heals any drift from the incremental cap-on-cursor bug and absorbs
    # any GHSA placeholders the GHSA pipeline created in the meantime.
    # Defaulted to Friday to spread the weekly load across the week (EUVD
    # is Sunday, NVD is Wednesday). The full sync is unbounded by record
    # count — it runs until the timeout (`INGESTION_RUNNING_TIMEOUT_MINUTES`)
    # or until every ecosystem ZIP is exhausted.
    scheduler_osv_full_sync_enabled: bool = True
    scheduler_osv_full_sync_cron_hour: int = 2  # 2 AM UTC
    scheduler_osv_full_sync_cron_day_of_week: str = "fri"  # Friday

    # SCA Scanning
    sca_enabled: bool = True
    sca_api_key: str | None = None
    sca_scanner_url: str = "http://scanner:8080"
    sca_scanner_timeout_seconds: int = 600
    sca_source_archive_max_bytes: int = 50 * 1024 * 1024
    sca_auto_scan_enabled: bool = False
    sca_auto_scan_interval_minutes: int = 1440
    sca_max_concurrent_scans: int = 2
    sca_min_free_memory_mb: int = 1024
    sca_min_free_disk_mb: int = 2048

    # Notifications (Apprise)
    notifications_enabled: bool = False
    notifications_apprise_url: str = "http://apprise:8000"
    notifications_apprise_tags: str = "all"
    notifications_apprise_timeout: int = 10
    notifications_watch_rule_limit: int = 100

    # MCP Server
    mcp_enabled: bool = False
    mcp_oauth_provider: str | None = None  # "github" | "microsoft" | "oidc"
    mcp_oauth_client_id: str = ""
    mcp_oauth_client_secret: str = ""
    mcp_oauth_issuer: str = ""  # OIDC discovery URL; for microsoft tenant URL
    mcp_oauth_scopes: str = ""  # space-separated; empty = provider default
    mcp_write_ip_safelist: str = ""  # CSV of IPs/CIDRs
    mcp_allowed_users: str = ""  # CSV of identities/emails; empty = any IdP-authenticated
    mcp_rate_limit_per_minute: int = 60
    mcp_max_results: int = 50
    mcp_max_concurrent_connections: int = 20

    trusted_proxy_ips_raw: str | None = Field(default=None, alias="trusted_proxy_ips")
    trusted_proxy_forward_header: str = "x-forwarded-for"
    trusted_proxy_real_ip_header: str | None = "x-real-ip"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def trusted_proxy_ips(self) -> list[str]:
        value = self.trusted_proxy_ips_raw
        if not value:
            return []
        items = [item.strip() for item in value.split(",")]
        return [item for item in items if item]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]


settings = get_settings()
