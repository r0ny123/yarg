from contextlib import contextmanager

Database = None
FlowChart = None


@contextmanager
def current_database():
    db = _database_cls().open()
    try:
        yield db
    finally:
        if _is_ida_library_mode():
            close = getattr(db, "close", None)
            if close is not None:
                close()
            return

        unhook = getattr(db, "unhook", None)
        if unhook is not None:
            unhook()


def _is_ida_library_mode() -> bool:
    ida_kernwin = None
    try:
        import ida_kernwin as imported_ida_kernwin

        ida_kernwin = imported_ida_kernwin
    except ModuleNotFoundError:
        try:
            from ida_domain import database as ida_database

            ida_kernwin = getattr(ida_database, "ida_kernwin", None)
        except Exception:
            ida_kernwin = None

    is_ida_library = getattr(ida_kernwin, "is_ida_library", None)
    if is_ida_library is None:
        return False

    try:
        return bool(is_ida_library(None, 0, None))
    except Exception:
        return False


def _database_cls():
    global Database
    if Database is None:
        from ida_domain import Database as imported_database

        Database = imported_database
    return Database


def _flowchart_cls():
    global FlowChart
    if FlowChart is None:
        from ida_domain.flowchart import FlowChart as imported_flowchart

        FlowChart = imported_flowchart
    return FlowChart


def get_function_at(db, ea):
    return db.functions.get_at(ea)


def iter_basic_blocks(db, func):
    return _flowchart_cls()(db, func)


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
