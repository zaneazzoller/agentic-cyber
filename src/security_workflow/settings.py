from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    log_level: str = "INFO"
    database_url: str = "postgresql+psycopg://security_workflow:security_workflow@localhost:5432/security_workflow"
    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_group_id: str = "security-workflow"
    vllm_base_url: str = "http://localhost:8000/v1"
    vllm_api_key: str | None = None
    splunk_base_url: str | None = None
    splunk_hec_url: str | None = None
    splunk_token: str | None = None
