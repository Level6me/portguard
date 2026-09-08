# -*- coding: utf-8 -*-
from controllers.stats_controller import (
    handle_stats, handle_report_export, handle_analytics
)
from controllers.settings_controller import (
    handle_settings_get, handle_config_snapshots, handle_config_backup,
    handle_compromise_check, handle_defense_toggle, handle_settings_post,
    handle_config_rollback
)
from controllers.logs_controller import (
    handle_events, handle_access_logs, handle_access_logs_clear
)
from controllers.security_controller import (
    handle_hidden_ips, handle_attacker_timeline, handle_ip_info,
    handle_blacklist, handle_whitelist, handle_blacklist_export,
    handle_unban, handle_ban, handle_ban_subnet, handle_batch_ban_all,
    handle_blacklist_import, handle_whitelist_add, handle_whitelist_delete,
    handle_whitelist_import, handle_hidden_ips_add, handle_hidden_ips_remove,
    handle_hidden_ips_clear, handle_hidden_ips_import, handle_hidden_ips_post_delete
)
from controllers.rules_controller import (
    handle_traps, handle_business_ports, handle_http_traps, handle_traps_export,
    handle_traps_add, handle_traps_edit, handle_traps_delete, handle_traps_toggle,
    handle_http_traps_toggle, handle_http_traps_add, handle_http_traps_edit,
    handle_http_traps_delete, handle_http_traps_import, handle_traps_import,
    handle_business_ports_add, handle_business_ports_edit,
    handle_business_ports_delete, handle_business_ports_import
)
from controllers.cluster_controller import (
    handle_cluster_nodes, handle_cluster_sync_unban,
    handle_cluster_sync_state_exchange, handle_cluster_sync_ban,
    handle_cluster_sync_whitelist, handle_cluster_sync_all_whitelist,
    handle_cluster_sync_all_mesh, handle_cluster_ping, handle_cluster_test_node,
    handle_cluster_nodes_add, handle_cluster_nodes_delete,
    handle_cluster_nodes_update_remark, handle_cluster_nodes_test_all,
    handle_cluster_nodes_test_single
)

GET_ROUTES = {
    "/api/stats": handle_stats,
    "/api/report/export": handle_report_export,
    "/api/analytics": handle_analytics,
    "/api/settings": handle_settings_get,
    "/api/config/snapshots": handle_config_snapshots,
    "/api/config/backup": handle_config_backup,
    "/api/compromise/check": handle_compromise_check,
    "/api/cluster/nodes": handle_cluster_nodes,
    "/api/hidden-ips": handle_hidden_ips,
    "/api/hidden_ips": handle_hidden_ips,
    "/api/hidden-ips/export": handle_hidden_ips,
    "/api/hidden_ips/export": handle_hidden_ips,
    "/api/events": handle_events,
    "/api/attacker/timeline": handle_attacker_timeline,
    "/api/ip_info": handle_ip_info,
    "/api/blacklist": handle_blacklist,
    "/api/blacklist/export": handle_blacklist_export,
    "/api/whitelist": handle_whitelist,
    "/api/whitelist/export": handle_whitelist,
    "/api/traps": handle_traps,
    "/api/traps/export": handle_traps_export,
    "/api/business_ports": handle_business_ports,
    "/api/business_ports/export": handle_business_ports,
    "/api/http_traps": handle_http_traps,
    "/api/http_traps/export": handle_http_traps,
    "/api/access_logs": handle_access_logs,
}

POST_ROUTES = {
    "/api/access_logs/clear": handle_access_logs_clear,
    "/api/unban": handle_unban,
    "/api/ban": handle_ban,
    "/api/defense/toggle_pause": handle_defense_toggle,
    "/api/settings": handle_settings_post,
    "/api/config/rollback": handle_config_rollback,
    "/api/blacklist/ban_subnet": handle_ban_subnet,
    "/api/blacklist/batch_ban_all": handle_batch_ban_all,
    "/api/blacklist/import": handle_blacklist_import,
    "/api/whitelist/add": handle_whitelist_add,
    "/api/whitelist/delete": handle_whitelist_delete,
    "/api/whitelist/import": handle_whitelist_import,
    "/api/hidden-ips": handle_hidden_ips_add,
    "/api/hidden_ips": handle_hidden_ips_add,
    "/api/hidden-ips/remove": handle_hidden_ips_remove,
    "/api/hidden_ips/remove": handle_hidden_ips_remove,
    "/api/hidden-ips/delete": handle_hidden_ips_remove,
    "/api/hidden_ips/delete": handle_hidden_ips_remove,
    "/api/hidden-ips/clear": handle_hidden_ips_clear,
    "/api/hidden_ips/clear": handle_hidden_ips_clear,
    "/api/hidden-ips/import": handle_hidden_ips_import,
    "/api/hidden_ips/import": handle_hidden_ips_import,
    "/api/traps/add": handle_traps_add,
    "/api/traps/edit": handle_traps_edit,
    "/api/traps/delete": handle_traps_delete,
    "/api/traps/toggle": handle_traps_toggle,
    "/api/traps/import": handle_traps_import,
    "/api/http_traps/toggle": handle_http_traps_toggle,
    "/api/http_traps/add": handle_http_traps_add,
    "/api/http_traps/edit": handle_http_traps_edit,
    "/api/http_traps/delete": handle_http_traps_delete,
    "/api/http_traps/import": handle_http_traps_import,
    "/api/business_ports/add": handle_business_ports_add,
    "/api/business_ports/edit": handle_business_ports_edit,
    "/api/business_ports/delete": handle_business_ports_delete,
    "/api/business_ports/import": handle_business_ports_import,
    "/api/cluster/sync_unban": handle_cluster_sync_unban,
    "/api/cluster/sync_state_exchange": handle_cluster_sync_state_exchange,
    "/api/cluster/sync_ban": handle_cluster_sync_ban,
    "/api/cluster/sync_whitelist": handle_cluster_sync_whitelist,
    "/api/cluster/sync_all_whitelist": handle_cluster_sync_all_whitelist,
    "/api/cluster/sync_all_mesh": handle_cluster_sync_all_mesh,
    "/api/cluster/sync_all_blacklist": handle_cluster_sync_all_mesh,
    "/api/cluster/ping": handle_cluster_ping,
    "/api/cluster/test_node": handle_cluster_test_node,
    "/api/cluster/nodes/add": handle_cluster_nodes_add,
    "/api/cluster/nodes/delete": handle_cluster_nodes_delete,
    "/api/cluster/nodes/update_remark": handle_cluster_nodes_update_remark,
    "/api/cluster/nodes/test_all": handle_cluster_nodes_test_all,
    "/api/cluster/nodes/test_single": handle_cluster_nodes_test_single,
}

DELETE_ROUTES = {
    "/api/hidden-ips": handle_hidden_ips_post_delete,
    "/api/hidden_ips": handle_hidden_ips_post_delete,
}

def dispatch_get(req, parsed):
    path = parsed.path
    handler = GET_ROUTES.get(path)
    if handler:
        handler(req, parsed)
        return True
    return False

def dispatch_post(req, parsed, req_data):
    path = parsed.path
    handler = POST_ROUTES.get(path)
    if handler:
        handler(req, parsed, req_data)
        return True
    return False

def dispatch_delete(req, parsed, req_data):
    path = parsed.path
    handler = DELETE_ROUTES.get(path)
    if handler:
        handler(req, parsed, req_data)
        return True
    return False
