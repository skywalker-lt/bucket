from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    master_secret: str = "change-me-to-a-long-random-string"
    pbkdf2_salt: str = "change-me-to-a-random-salt"
    pbkdf2_iterations: int = 600_000

    rp_id: str = "localhost"
    rp_name: str = "CatVault"
    rp_origin: str = "https://localhost"

    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_verify_service_sid: str = ""
    owner_phone_number: str = ""

    session_secret: str = "change-me-session-secret"

    storage_path: str = "./storage"
    database_path: str = "./data/vault.db"

    max_upload_size: int = 104_857_600  # 100 MB

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
