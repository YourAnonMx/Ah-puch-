import requests
from requests.adapters import HTTPAdapter
from .cache import get as _cget, put as _cput

_session = requests.Session()
adapter = HTTPAdapter(pool_maxsize=20)
_session.mount("https://", adapter)
_session.mount("http://", adapter)

def get_session():
    return _session


def cached_get(url, **kwargs):
    cached = _cget(url)
    if cached:
        return cached
    resp = _session.get(url, **kwargs)
    if resp.status_code == 200:
        _cput(url, resp.text)
    return resp
