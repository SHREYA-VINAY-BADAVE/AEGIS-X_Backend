import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "Intelligent Phishing Detection Using Machine Learning"
    
    # MongoDB settings
    MONGODB_URI: str = "mongodb+srv://abhijeetbirajdar90_db_user:<db_password>@cluster0.ohr9qor.mongodb.net/?appName=Cluster0"
    DATABASE_NAME: str = "phishing_detection"
    
    # JWT authentication settings
    JWT_SECRET: str = "supersecretsecuritykeyforphishingapp1234!"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Admin settings
    ADMIN_EMAIL: str = "admin@aegis-x.ai"
    ADMIN_PASSWORD: str = "AdminGuard2026!"
    
    # External APIs
    VIRUSTOTAL_API_KEY: str = ""
    GOOGLE_SAFE_BROWSING_API_KEY: str = ""
    GOOGLE_CLIENT_ID: str = ""
    
    class Config:
        env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
        extra = "ignore"

settings = Settings()
