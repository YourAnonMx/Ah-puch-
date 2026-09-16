import shelve, time, pathlib, hashlib, os

CACHE_FILE = pathlib.Path.home() / ".ah_puch_cache"
CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
TTL = 86400

def _key(url: str) -> str:
    return hashlib.sha256(url.encode()).hexdigest()

def get(url: str):
    key = _key(url)
    with shelve.open(str(CACHE_FILE)) as db:
        data = db.get(key)
        if not data:
            return None
        if time.time() - data["t"] > TTL:
            return None
        return data["d"]

def put(url: str, content: str):
    key = _key(url)
    with shelve.open(str(CACHE_FILE)) as db:
        db[key] = {"d": content, "t": time.time()}
