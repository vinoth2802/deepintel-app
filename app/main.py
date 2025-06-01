from fastapi import FastAPI, APIRouter
from app.api.dns_routes import router as dnstwist_router
from fastapi.middleware.cors import CORSMiddleware

# Create FastAPI application instance
app = FastAPI()

# Enable CORS middleware to allow frontend/backend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

# Create a top-level APIRouter
router = APIRouter()

# Include your DNS-related router under the '/dns-search' path
router.include_router(dnstwist_router, prefix="/dns-search")

# Include the top-level router into the main FastAPI app with a global '/api' prefix
app.include_router(router, prefix="/api")
