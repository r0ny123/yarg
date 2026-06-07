from contextlib import contextmanager

from ida_domain import Database
from ida_domain.flowchart import FlowChart


@contextmanager
def current_database():
    db = Database.open()
    try:
        yield db
    finally:
        close = getattr(db, "close", None)
        if close is not None:
            close()


def get_function_at(db, ea):
    return db.functions.get_at(ea)


def iter_basic_blocks(db, func):
    return FlowChart(db, func)


def has_xrefs_to(db, ea: int) -> bool:
    if db is None or not hasattr(db, "xrefs"):
        return False

    xrefs_api = db.xrefs
    refs_to = getattr(xrefs_api, "to_ea", None) or getattr(xrefs_api, "to", None)
    if refs_to is None:
        return False

    try:
        return any(True for _ in refs_to(ea))
    except Exception:
        return False
