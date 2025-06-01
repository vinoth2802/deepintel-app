import redis

# -----------------------
# Redis Configuration
# -----------------------
REDIS_HOST = 'localhost'
REDIS_PORT = 6379
REDIS_DB = 1
WHOIS_CACHE_EXPIRY_SECONDS = 345600  # cache WHOIS results for 4 days (345600 seconds)
THROTTLE_DELAY_SECONDS = 1           # Sleep 1 second between WHOIS calls to avoid rate limiting

# Initialize Redis connection
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)