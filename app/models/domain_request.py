from pydantic import BaseModel
from typing import List, Optional

class DomainRequest(BaseModel):
    domain: str
    fuzzers: Optional[List[str]] = None
    dictionary: Optional[str] = None
    tld: Optional[str] = None
    output_format: str = "json"
    threads: int = 4
    registered: bool = False
    unregistered: bool = False
    geoip: bool = False
    lsh: Optional[str] = None
    phash: bool = False
    screenshots: Optional[str] = None
    whois: bool = False
