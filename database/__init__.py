# database/__init__.py
from .db_session import (
    init_db,
    get_db_connection,
    save_scan,
    get_scan_by_id,
    get_all_scans,
    delete_scan,
    get_scan_findings,
    get_scan_leakage_alerts,
    get_rule_configs,
    update_rule_status,
    get_dashboard_stats
)

__all__ = [
    "init_db",
    "get_db_connection",
    "save_scan",
    "get_scan_by_id",
    "get_all_scans",
    "delete_scan",
    "get_scan_findings",
    "get_scan_leakage_alerts",
    "get_rule_configs",
    "update_rule_status",
    "get_dashboard_stats"
]
