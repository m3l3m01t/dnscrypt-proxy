#include <dnscrypt/plugin.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include <ldns/ldns.h>

#include "config.h"

DCPLUGIN_MAIN(__FILE__);

#ifdef USE_MYSQL
#include <mysql.h>
#endif

#ifdef USE_MEMCACHED
#include <libmemcached/memcached.h>
#endif

typedef enum {POLICY_UNKNOWN, POLICY_DEFAULT, POLICY_DIRECT, POLICY_PROXY, POLICY_BLOCK} policy_type_t;

struct plugin_priv_data {
    FILE *fp;
#ifdef USE_MYSQL
    MYSQL mysql;
    int connected;
#endif
#ifdef USE_MEMCACHED
    memcached_st *memc;
#endif
} _priv_data;

#ifdef USE_MEMCACHED
#define MEMCACHED_SOCKET "/var/run/memcached/memcached.socket"
const char *memcached_opt = "--SOCKET=" MEMCACHED_SOCKET;

static void
dcplugin_init_memcached(struct plugin_priv_data *data)
{
    memcached_st *memc;

    fprintf(data->fp, "init memcached\n");
    fflush(data->fp);

    memc = memcached_create(NULL);

    if (memcached_server_add_unix_socket(memc, MEMCACHED_SOCKET) == MEMCACHED_SUCCESS) {
        fprintf(data->fp, "memcached added\n");
        fflush(data->fp);

        memcached_behavior_set(memc, MEMCACHED_BEHAVIOR_BINARY_PROTOCOL, 1);
        data->memc = memc;
    } else {
        fprintf(data->fp, "failed to connect memcached:%s\n", memcached_last_error_message(memc));
        fflush(data->fp);
        memcached_free (memc);
    }
}

static void
_memcached_set_ip_policy(memcached_st *memc, ldns_rdf *rdf, policy_type_t policy, const char *domain_name)
{
    if (memc) {
        fprintf(_priv_data.fp, "memcache ipaddr %s, policy %d\n",
                ldns_rdf2str(rdf), policy);
        if (memcached_set_by_key(memc, "ip", 2, ldns_rdf_data(rdf),
                    ldns_rdf_size(rdf), (const char *)&policy, sizeof(policy),
                    0, 0) != MEMCACHED_SUCCESS) {
            fprintf(_priv_data.fp, "ERROR: set %s policy %d failed: %s\n", 
                    memcached_last_error_message(memc));
        };
        fflush(_priv_data.fp);
    }
}
#endif

#ifdef USE_MYSQL

#define MYSQL_USER "pi"
#define MYSQL_PASS "raspberry"
#define MYSQL_DB   "dns"

static MYSQL *
get_mysql(struct plugin_priv_data *priv)
{
    if (priv->connected == 0) {
        if (mysql_real_connect(&priv->mysql, "127.0.0.1", 
                    MYSQL_USER, MYSQL_PASS, MYSQL_DB, 3306, NULL, 0) == NULL) {
            fprintf(priv->fp, "connect to mysql failed(%d):%s\n",
                    mysql_errno(&priv->mysql), mysql_error(&priv->mysql));
            return NULL;
        } 
        priv->connected = 1;
    }
    return &priv->mysql;
}

#define TABLE_NAME_DOMAIN  "domain"
#define TABLE_NAME_IP  "ip"

#define TABLE_FIELD_DOMAIN "domain"
#define TABLE_FIELD_LVL    "levels"

#define DOMAIN_LVLS_MAX 5
static policy_type_t
_mysql_query_domain_policy(MYSQL *mysql, const char *domain)
{
    int lvl = 0;

    int statement_len;
    const static char statement_tail[] = "ORDER BY " TABLE_FIELD_LVL " DESC LIMIT 1";
    char sql_statement[2048] = "SELECT * FROM " TABLE_NAME_DOMAIN " where ";
    policy_type_t policy = POLICY_DEFAULT;

    const char *d;

    /* domain must ends with '.' */
    for (d = domain; *d; d++) {
        if (*d == '.')
            lvl ++;
    }

    d = domain;

#if 1
    MYSQL_RES *results;
    MYSQL_ROW record;
   
    statement_len = strlen(sql_statement);
    while(lvl-- > 0) {
        char buf[256];
        if (lvl < DOMAIN_LVLS_MAX) {
            int len = snprintf(buf, sizeof(buf) - 1, "(" TABLE_FIELD_DOMAIN " = '%s')%s ", d,
                    lvl > 0 ? " OR" : "");
            strncat(sql_statement, buf, sizeof(sql_statement) - sizeof(statement_tail) - statement_len);

            statement_len += len;
        }

        while (*d++ != '.');
    }

    if (sizeof(sql_statement) - statement_len <= sizeof(statement_tail)) {
        fprintf(_priv_data.fp, "domain too long: %s\n", domain);
        return policy;
    }

    strcat(sql_statement, statement_tail);

#ifdef DEBUG
    fprintf(_priv_data.fp, "query domain policy: %s\n", sql_statement);
#endif

    if (mysql_query(mysql, sql_statement) != 0) {
        /* query failed */
        fprintf(_priv_data.fp, "query domain policy failed:%s\n",
                mysql_error(mysql));
    } else if (mysql_field_count(mysql) > 0) {
        results = mysql_store_result(mysql);

        while((record = mysql_fetch_row(results))) {
            policy = strtoul(record[2], NULL, 10);
#ifdef DEBUG
            fprintf(_priv_data.fp, "%s, levels %s, policy %s\n", record[0], record[1], record[2]);
#endif
        }

        mysql_free_result(results);
    }

#else
    while ((policy == POLICY_DEFAULT) && (lvl > 0)) {
        MYSQL_RES *results;
        MYSQL_ROW record;

        snprintf(sql_statement, sizeof(sql_statement) - 1, "SELECT * FROM " TABLE_NAME_DOMAIN " where (" TABLE_FIELD_LVL " = %u AND " TABLE_FIELD_DOMAIN " = '%s')", lvl--, d);

#ifdef DEBUG
        fprintf(_priv_data.fp, "query domain policy: %s\n", sql_statement);
#endif

        if (mysql_query(mysql, sql_statement) != 0) {
            /* query failed */
#ifdef DEBUG
            fprintf(_priv_data.fp, "query domain policy failed:%s\n",
                   mysql_error(mysql));
#endif
            break;
        }

        while (*d++ != '.');

        if (mysql_field_count(mysql) == 0) {
            continue;
        }

        results = mysql_store_result(mysql);

        while((record = mysql_fetch_row(results))) {
            unsigned int levels;

            levels = strtoul(record[1], NULL, 10);
            policy = strtoul(record[2], NULL, 10);
#ifdef DEBUG
            fprintf(_priv_data.fp, "%s,levels ptr %p: %s-%d, policy ptr %p:%s-%d\n", record[0], record[1], record[1],levels,record[2], record[2],policy);
#endif
        }

        mysql_free_result(results);
    }
#endif

    return policy;
}

static void
_mysql_set_ip_policy(MYSQL *mysql, const char *addr,
        policy_type_t policy, const char *domain)
{
    char statement[128];

    snprintf(statement, sizeof(statement) - 1, 
        "REPLACE INTO " TABLE_NAME_IP " (ip, policy, dname) VALUES('%s',%d,'%s')" , 
        addr,(int)policy,domain);

    fprintf(_priv_data.fp, "update ip policy: %s\n", statement);
    if (mysql_query(mysql, statement)) {
        fprintf(_priv_data.fp, "update ip policy failed: %s\n",
            mysql_error(mysql));
    }
}


#endif

const char *
dcplugin_description(DCPlugin * const dcplugin)
{
    return "Log client queries";
}

const char *
dcplugin_long_description(DCPlugin * const dcplugin)
{
    return
        "Log client queries\n"
        "\n"
        "This plugin logs the client queries to the standard output (default)\n"
        "or to a file.\n"
        "\n"
        "  # dnscrypt-proxy --plugin libdcplugin_example_logging,/tmp/dns.log";
}

int
dcplugin_init(DCPlugin * const dcplugin, int argc, char *argv[])
{
    FILE *fp;

    if (argc != 2U) {
        fp = stdout;
    } else {
        if ((fp = fopen(argv[1], "w")) == NULL) {
            return -1;
        }
    }
    _priv_data.fp = fp;

#ifdef USE_MYSQL
    mysql_library_init(0, NULL, NULL);
    mysql_init(&_priv_data.mysql);
    my_bool reconnect = 1;

    mysql_options(&_priv_data.mysql, MYSQL_OPT_RECONNECT, &reconnect);
    _priv_data.connected = 0;
#endif

#ifdef USE_MEMCACHED
    _priv_data.memc = NULL;
    dcplugin_init_memcached(&_priv_data);
#endif


    dcplugin_set_user_data(dcplugin, &_priv_data);

    return 0;
}

int
dcplugin_destroy(DCPlugin * const dcplugin)
{
    struct plugin_priv_data *priv = dcplugin_get_user_data(dcplugin);

    if (priv->fp != stdout) {
        fclose(priv->fp);
    }
#ifdef USE_MYSQL
    mysql_close(&priv->mysql);
    mysql_library_end();
#endif
#ifdef USE_MEMCACHE
    if (priv->memc) {
        memcached_free(priv->memc);
    }
#endif
    return 0;
}

DCPluginSyncFilterResult
dcplugin_sync_post_filter(DCPlugin *dcplugin, DCPluginDNSPacket *dcp_packet)
{
    struct plugin_priv_data *priv = dcplugin_get_user_data(dcplugin);
    FILE     *fp = priv->fp;

    ldns_pkt *resp = NULL;

    ldns_rr_list *list;
    uint8_t  *wire_data = dcplugin_get_wire_data(dcp_packet);
    size_t   wire_data_len = dcplugin_get_wire_data_len(dcp_packet);
    char *domain_name = NULL;
    

    if (LDNS_RCODE_WIRE(wire_data) != LDNS_RCODE_NOERROR) {
        return DCP_SYNC_FILTER_RESULT_OK;
    }

    if (ldns_wire2pkt(&resp, wire_data, dcplugin_get_wire_data_len(dcp_packet)) != LDNS_STATUS_OK)
        return DCP_SYNC_FILTER_RESULT_OK;

    list = ldns_pkt_question(resp);

    if (ldns_rr_list_rr_count(list) != 1)
        goto packet_end;

    ldns_rr * rr = ldns_rr_list_rr(list, 0);
    ldns_rr_class klz = ldns_rr_get_class(rr);
    ldns_rr_type type = ldns_rr_get_type(rr);

    if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) {
        goto packet_end;
    }

    domain_name = ldns_rdf2str(ldns_rr_owner(rr));

    fprintf(fp, "Question: %s\n", domain_name);
#ifdef USE_MYSQL
    policy_type_t policy; 

    MYSQL *mysql = get_mysql(priv);
    if (mysql == NULL) {
        goto packet_end;
    }

    policy = _mysql_query_domain_policy(mysql, domain_name);

    if (policy == POLICY_DEFAULT) {
        goto packet_end;
    }
#endif

    list = ldns_pkt_answer (resp);

    for (int i = 0; list && i < ldns_rr_list_rr_count(list); i++) {
        ldns_rr * rr = ldns_rr_list_rr(list, i);
        ldns_rr_class klz = ldns_rr_get_class(rr);
        ldns_rr_type type = ldns_rr_get_type(rr);

        if (type != LDNS_RR_TYPE_A && type != LDNS_RR_TYPE_AAAA) {
            continue;
        } 

        for (int j = 0; j < ldns_rr_rd_count(rr); j++) {
            ldns_rdf *rdf = ldns_rr_rdf(rr, j);
            int rdf_sz = ldns_rdf_size(rdf);

            ldns_rdf_type rdf_type = ldns_rdf_get_type(rdf);

            if (rdf_type == LDNS_RDF_TYPE_A || rdf_type == LDNS_RDF_TYPE_AAAA) {
                char *ipaddr = ldns_rdf2str(rdf);
#ifdef USE_MYSQL
                _mysql_set_ip_policy(mysql, ipaddr, policy, domain_name);
#endif
#ifdef USE_MEMCACHED
                _memcached_set_ip_policy(priv->memc, rdf, policy, domain_name);
#endif
                free(ipaddr);
            }
        }
    }

packet_end:
    if (domain_name)
        free(domain_name);

    ldns_pkt_free(resp);

    fflush(fp);

    return DCP_SYNC_FILTER_RESULT_OK;
}
/* vim: set ts=4 sw=4 et: */
