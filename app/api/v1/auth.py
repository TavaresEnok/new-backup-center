from fastapi import APIRouter

router = APIRouter()

@router.get("/login")
async def login_api():
    return {"message": "API Login placeholder"}
