import asyncio
import traceback

from fastapi import APIRouter, Request, HTTPException
from starlette.requests import ClientDisconnect

from app.models.domain_request import DomainRequest
from app.services.dns_service import  process_whois, evaluate_phishing_risk
from app.services.dns_service import perform_fuzzing
from app.services.format import Format
import logging

router = APIRouter()

logging.basicConfig(level=logging.DEBUG)

# Endpoint for domain fuzzing
@router.post("/fuzz/{domain}")
async def fuzz(domain:str):
    try:
        domains = perform_fuzzing(domain = domain)
        logging.debug("Fuzzer generated domains count: %d", len(domains))
        return domains
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Endpoint for domain fuzzing
@router.post("/whois/{domain}")
async def whois(domain:str):
    try:
        domains = perform_fuzzing(domain = domain)
        logging.debug("Fuzzer generated domains count: %d", len(domains))
        whois_looked_up_domains = process_whois(domains, domain)
        logging.debug("WHOIS looked up domains count: %d", len(whois_looked_up_domains))
        return whois_looked_up_domains
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Endpoint for phishing detection

@router.post("/screenshot/{domain}")
async def evaluate_screenshot(domain: str, request: Request):
    try:
        if await request.is_disconnected():
            raise HTTPException(status_code=499, detail="Client closed the connection")

        domains = perform_fuzzing(domain=domain)
        logging.debug("Fuzzer generated domains count: %d", len(domains))

        whois_looked_up_domains = process_whois(domains, domain)
        logging.debug("WHOIS looked up domains count: %d", len(whois_looked_up_domains))

        if await request.is_disconnected():
            raise HTTPException(status_code=499, detail="Client closed the connection")

        # Run long blocking task in a separate thread
        result = await asyncio.to_thread(evaluate_phishing_risk, domain, whois_looked_up_domains)

        # Optional: one more disconnection check before returning
        if await request.is_disconnected():
            raise HTTPException(status_code=499, detail="Client closed the connection")

        return result

    except ClientDisconnect:
        logging.warning("Client disconnected during processing.")
        raise HTTPException(status_code=499, detail="Client disconnected")

    except Exception as e:
        logging.error("Internal server error: %s", str(e))
        raise HTTPException(status_code=500, detail=str(e))
#
# # Endpoint for domain fuzzing with WHOIS and screenshots
# @router.post("/scan-domain")
# async def scan_domain_endpoint(request: DomainRequest):
#     # Validating parameters
#     if request.threads < 1:
#         raise HTTPException(status_code=400, detail="Number of threads must be greater than zero")
#     if request.output_format not in ["csv", "json", "list"]:
#         raise HTTPException(status_code=400, detail="Invalid output format")
#
#     # Call the service logic to handle domain scanning
#     try:
#         domains = scan_domain(
#             domain=request.domain,
#             fuzzers=request.fuzzers,
#             dictionary=request.dictionary,
#             tld=request.tld,
#             whois=request.whois,
#             screenshots=request.screenshots,
#             geoip=request.geoip
#         )
#
#         # Return the result based on requested output format
#         if request.output_format == "list":
#             return {"domains": [domain["domain"] for domain in domains]}
#         elif request.output_format == "csv":
#             return {"domains": Format(domains).csv()}
#         elif request.output_format == "json":
#             return {"domains": Format(domains)}
#
#         return {"domains": domains}
#     except Exception as e:
#         traceback.print_exc()
#         raise HTTPException(status_code=500, detail=str(e))
#
#
# # Endpoint for scanning with specific flags (e.g., WHOIS, screenshots, geoip, etc.)
# @router.post("/scan-with-flags")
# async def scan_with_flags(request: DomainRequest):
#     # Checking if any flag is set for scanning
#     if not (request.whois or request.screenshots or request.geoip):
#         raise HTTPException(status_code=400, detail="At least one flag must be enabled (whois, screenshots, geoip).")
#
#     # Call the service logic to handle domain scanning
#     try:
#         domains = scan_domain(
#             domain=request.domain,
#             fuzzers=request.fuzzers,
#             dictionary=request.dictionary,
#             tld=request.tld,
#             whois=request.whois,
#             screenshots=request.screenshots,
#             geoip=request.geoip
#         )
#
#         return {"domains": domains}
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=str(e))
#
