from app import create_main_app
from app.core.database import engine, Base
from app.core.config import settings
import app.models # Ensure models are imported for create_all
import uvicorn

# Create tables if configured (dev convenience)
if settings.AUTO_CREATE_SCHEMA:
    Base.metadata.create_all(bind=engine)

app = create_main_app()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
