from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "postgresql+psycopg://integrity:integrity@localhost:5432/integrity"
    redis_url: str = "redis://localhost:6379/0"
    secret_pepper: str = "change-this-pepper-outside-dev"
    wasm_envelope_key: str = "local-dev-wasm-envelope-key"
    cors_origins: str = "http://localhost:5173"
    replay_window_seconds: int = 30
    base_rate_limit_per_minute: int = 90
    burst_rate_limit_per_10_seconds: int = 25

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def cors_origin_list(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
