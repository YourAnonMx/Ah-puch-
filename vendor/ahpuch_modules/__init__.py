

import importlib, sys as _sys
from types import ModuleType as _Mod

try:
    from . import utils as _u
    _sys.modules.setdefault("utils", _u)
except ImportError:
    pass
