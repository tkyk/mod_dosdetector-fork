/*
 * Copyright (C) 2007 Hatena Inc.
 * The author is Shinji Tanaka <stanaka@hatena.ne.jp>.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice, this permission notice, and the
 * following disclaimer shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 */

#include <arpa/inet.h>
#include <time.h>
#include "httpd.h"
#include "http_config.h"
#include "http_request.h"
#include "http_protocol.h"
#include "http_core.h"
#include "http_main.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_shm.h"
#include "util_mutex.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(dosdetector);
#endif

#ifdef _DEBUG
#define DEBUGLOG(...) ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, NULL, __VA_ARGS__)
#define DEBUGLOG_R(...) ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, __VA_ARGS__)
#else
#define DEBUGLOG(...)   //
#define DEBUGLOG_R(...) //
#endif

#define USER_DATA_KEY "DoSDetecterUserDataKey"

#define DEFAULT_THRESHOLD 10000
#define DEFAULT_PERIOD 10
#define DEFAULT_BAN_PERIOD 300
#define DEFAULT_TABLE_SIZE 100

module AP_MODULE_DECLARE_DATA dosdetector_module;

struct s_client {
    struct in_addr addr;
    int count;
    time_t interval;
    time_t last;
    struct s_client* next;
    time_t suspected;
    time_t hard_suspected;
};
typedef struct s_client client_t;

typedef struct {
    client_t *head;
    client_t base[1];
} client_list_t;

typedef struct {
    signed int detection;
    signed int threshold;
    signed int ban_threshold;
    signed int period;
    signed int ban_period;
    apr_array_header_t *ignore_contenttype;
    apr_array_header_t *contenttype_regexp;
} dosdetector_dir_config;

typedef enum {
    NORMAL,
    SUSPECTED,
    SUSPECTED_FIRST,
    SUSPECTED_HARD,
    SUSPECTED_HARD_FIRST
} client_status_e;

static long table_size  = DEFAULT_TABLE_SIZE;
const char *shmname = NULL;

static client_list_t *client_list;
static const char *mutex_id = "dosdetector-shm";
static apr_global_mutex_t *lock = NULL;
static apr_shm_t *shm = NULL;


static apr_status_t cleanup_shm(void *not_used)
{
    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, ap_server_conf, "Notice: cleaning up shared memory");
    fflush(stderr);

    if (shm) {
        apr_shm_destroy(shm);
        shm = NULL;
    }

    if (lock) {
        apr_global_mutex_destroy(lock);
        lock = NULL;
    }

    return APR_SUCCESS;
}

static void log_and_cleanup(char *msg, apr_status_t status, server_rec *s)
{
    ap_log_error(APLOG_MARK, APLOG_ERR, status, s, "Error: %s", msg);
    cleanup_shm(NULL);
}

static apr_status_t create_shm(server_rec *s,apr_pool_t *p)
{    
    size_t size;
    apr_status_t rc;

    size =  sizeof(client_list_t) + table_size * sizeof(client_t);

    if(shmname != NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "creating named shared memory '%s'", shmname);
        rc = apr_shm_remove(shmname, p);
        if (APR_SUCCESS == rc) {
            ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s,
                    "removed the existing shared memory segment named '%s'", shmname);
        }
    } else {
	    ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, s, "creating anonymous shared memory");
    }
    
    rc = apr_shm_create(&shm, size, shmname, p);
    if (APR_SUCCESS != rc) {
        ap_log_error(APLOG_MARK, APLOG_ERR, rc, s, "failed to create shared memory");
        return rc;
    }
    client_list = apr_shm_baseaddr_get(shm);
    memset(client_list, 0, size);

    if(shmname != NULL) {
        /* prevent other processes from accessing the segment */
        apr_shm_remove(shmname, p);
    }

    client_list->head = client_list->base;
    client_t *c = client_list->base;
    int i;

    for (i = 1; i < table_size; i++) {
        c->next = (c + 1);
        c++;
    }
    c->next = NULL;
    return APR_SUCCESS;
}

static client_t *get_client(client_list_t *client_list, struct in_addr clientip, int period)
{
    //ap_log_error(APLOG_MARK, APLOG_NOTICE, 0, 0, "get_client: looking %d", clientip.s_addr);
    client_t *index, **prev = &client_list->head;
    
    for(index = client_list->head; index->next != (client_t *) 0; index = index->next){
        if(index->addr.s_addr == 0 || index->addr.s_addr == clientip.s_addr)
            break;
        prev = &index->next;
    }

    if(index == (client_t *) 0)
        return (client_t *)0;

    *prev = index->next;
    index->next = client_list->head;
    client_list->head = index;

    time_t now = time((time_t*)0);
    int rest;
    if(now - index->last > period){
        index->interval = (now - index->last) / period;
        rest = (now - index->last) % period;
        index->last = now - rest;
    } else {
        index->interval = 0;
    }
    if(index->addr.s_addr != clientip.s_addr){
        index->count = 0;
        index->interval = 0;
        index->suspected = 0;
        index->hard_suspected = 0;
        index->addr = clientip;
    }

    return index;
}

static void *dosdetector_create_dir_config(apr_pool_t *p, char *path)
{
    //DEBUGLOG("create dir is called");
    dosdetector_dir_config *cfg = (dosdetector_dir_config *)
        apr_pcalloc(p, sizeof (*cfg));
    
    /* default configuration: no limit, and both arrays are empty */
    cfg->detection = 1;
    cfg->threshold = DEFAULT_THRESHOLD;
    cfg->period    = DEFAULT_PERIOD;
    cfg->ban_period    = DEFAULT_BAN_PERIOD;
    cfg->ignore_contenttype = apr_array_make(p, 0, sizeof(char *));
    cfg->contenttype_regexp = apr_array_make(p, 0, sizeof(char *));

    return (void *) cfg;
}

static void count_increment(client_t *client, int threshold)
{
    client->count = client->count - client->interval * threshold;
    if(client->count < 0)
        client->count = 0;
    client->count ++;
    
    return;
}

static int is_contenttype_ignored(dosdetector_dir_config *cfg, request_rec *r)
{
    const char *content_type;
    content_type = ap_sub_req_lookup_uri(r->uri, r, NULL)->content_type;
    
    ap_regmatch_t regmatch[AP_MAX_REG_MATCH];
    ap_regex_t **contenttype_regexp = (ap_regex_t **) cfg->contenttype_regexp->elts;
    
    int i, ignore = 0;
    for (i = 0; i < cfg->contenttype_regexp->nelts; i++) {
        if(!ap_regexec(contenttype_regexp[i], content_type, AP_MAX_REG_MATCH, regmatch, 0)) {
            ignore = 1;
            break;
        }
    }
    DEBUGLOG_R("content-type=%s, result=%s", content_type, (ignore ? "ignored":"processed"));
    return ignore;
}

static client_status_e update_client_status(client_t *client, dosdetector_dir_config *cfg, time_t now)
{
    client_status_e status = NORMAL;
    count_increment(client, cfg->threshold);

    if(client->suspected > 0 && client->suspected + cfg->ban_period > now){
        status = SUSPECTED;
        if(client->count > cfg->ban_threshold){
            status = SUSPECTED_HARD;
            if(client->hard_suspected == 0) status = SUSPECTED_HARD_FIRST;
            client->hard_suspected = now;
        }
    } else {
        if(client->suspected > 0){
            client->suspected = 0;
            client->hard_suspected = 0;
            client->count = 0;
        }

        if(client->count > cfg->threshold){
            status = SUSPECTED_FIRST;
            client->suspected = now;
        }
    }
    return status;
}

static int dosdetector_read_request(request_rec *r)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) ap_get_module_config(r->per_dir_config, &dosdetector_module);
    
    if(cfg->detection) return DECLINED;
    if(!ap_is_initial_req(r)) return DECLINED;

    if(apr_table_get(r->subprocess_env, "NoCheckDoS")) {
        DEBUGLOG_R("'NoCheckDoS' is set, skipping DoS check for %s", r->uri);
        return OK;
    }

    if(cfg->contenttype_regexp->nelts > 0 && is_contenttype_ignored(cfg, r)) {
        return OK;
    }

    const char *address;
    address = r->useragent_ip;

    struct in_addr addr;
    addr = r->useragent_addr->sa.sin.sin_addr;
    if(addr.s_addr == 0){
        inet_aton(address, &addr);
    }

    time_t now = time(NULL);

    /* enter the critical section */
    if (lock) apr_global_mutex_lock(lock);

    client_t *client = get_client(client_list, addr, cfg->period);
    #ifdef _DEBUG
    int last_count = client->count;
    #endif

    client_status_e status = update_client_status(client, cfg, now);
    DEBUGLOG_R("%s, count: %d -> %d, interval: %d",
             address, last_count, client->count, (int)client->interval);

    if (lock) apr_global_mutex_unlock(lock);
    /* leave the critical section */

    switch(status)
    {
    case SUSPECTED_FIRST:
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                "'%s' is suspected as DoS attack! (counter: %d)", address, client->count);
        apr_table_setn(r->subprocess_env, "SuspectDoS", "1");
        break;

    case SUSPECTED_HARD_FIRST:
        ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
                "'%s' is suspected as Hard DoS attack! (counter: %d)", address, client->count);
        apr_table_setn(r->subprocess_env, "SuspectHardDoS", "1");
        apr_table_setn(r->subprocess_env, "SuspectDoS", "1");
        break;

    case SUSPECTED_HARD:
        apr_table_setn(r->subprocess_env, "SuspectHardDoS", "1");
    case SUSPECTED:
        apr_table_setn(r->subprocess_env, "SuspectDoS", "1");
        DEBUGLOG_R("'%s' has been still suspected as DoS attack! (suspected %d sec ago)", address, (int)(now - client->suspected));
        break;

    case NORMAL:
        break;
    }
    return DECLINED;
}

static const char *set_detection_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;

    cfg->detection = ap_strcasecmp_match("on", arg);
    return NULL;
}

static const char *set_threshold_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int threshold = strtol(arg, (char **) NULL, 10);
    if ((threshold > 65535) || (threshold < 0)) return "Integer invalid number";

    cfg->threshold = threshold;
    return NULL;
}

static const char *set_hard_threshold_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int ban_threshold = strtol(arg, (char **) NULL, 10);
    if ((ban_threshold > 65535) || (ban_threshold < 0)) return "Integer invalid number";

    cfg->ban_threshold = ban_threshold;
    return NULL;
}

static const char *set_period_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int period = strtol(arg, (char **) NULL, 10);
    if ((period > 65535) || (period < 0)) return "Integer invalid number";

    cfg->period = period;
    return NULL;
}

static const char *set_ban_period_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;
    signed long int ban_period = strtol(arg, (char **) NULL, 10);
    if ((ban_period > 65535) || (ban_period < 0)) return "Integer overflow or invalid number";

    cfg->ban_period = ban_period;
    return NULL;
}

static const char *set_shmem_name_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    shmname = arg;
    return NULL;
}

static const char *set_table_size_config(cmd_parms *parms, void *mconfig, const char *arg)
{
    signed long int size = strtol(arg, (char **) NULL, 10);
    if ((size > 65535) || (size < 0)) return "Integer invalid number";

    table_size = size;
    return NULL;
}

static const char *set_ignore_contenttype_config(cmd_parms *parms, void *mconfig,
                     const char *arg)
{
    dosdetector_dir_config *cfg = (dosdetector_dir_config *) mconfig;

    *(char **) apr_array_push(cfg->ignore_contenttype) = apr_pstrdup(parms->pool, arg);
    *(ap_regex_t **)apr_array_push(cfg->contenttype_regexp)
        = ap_pregcomp(parms->pool, arg, AP_REG_EXTENDED|AP_REG_ICASE);

    return NULL;
}

static command_rec dosdetector_cmds[] = {
    AP_INIT_TAKE1("DoSDetection", set_detection_config, NULL, OR_FILEINFO,
     "Enable to detect DoS Attack or not"),
    AP_INIT_TAKE1("DoSThreshold", set_threshold_config, NULL, OR_FILEINFO,
     "Threshold of detecting DoS Attack"),
    AP_INIT_TAKE1("DoSHardThreshold", set_hard_threshold_config, NULL, OR_FILEINFO,
     "Hard Threshold for DoS Attack"),
    AP_INIT_TAKE1("DoSPeriod", set_period_config, NULL, OR_FILEINFO,
     "Period of detecting DoS Attack"),
    AP_INIT_TAKE1("DoSBanPeriod", set_ban_period_config, NULL, OR_FILEINFO,
     "Period of banning client"),
    AP_INIT_TAKE1("DoSShmemName", set_shmem_name_config, NULL, OR_FILEINFO,
     "The name of shared memory to allocate for keeping track of clients"),
    AP_INIT_TAKE1("DoSTableSize", set_table_size_config, NULL, OR_FILEINFO,
     "The size of table for tracking clients"),
    AP_INIT_ITERATE("DoSIgnoreContentType", set_ignore_contenttype_config, NULL, OR_FILEINFO,
     "The names of ignoring Content Type"),
    {NULL},
};

static int dosdetector_pre_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptmp)
{
    apr_status_t rv = ap_mutex_register(p, mutex_id, NULL, APR_LOCK_DEFAULT, 0);

    DEBUGLOG("Register global mutex %s", mutex_id);
    if (rv != APR_SUCCESS) {
        ap_log_error(APLOG_MARK, APLOG_INFO, 0, ap_server_conf,
                "failed to register %s mutex", mutex_id);
        return 500;
    }

    return OK;
}


static int dosdetector_post_config(apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
    void *user_data;
    apr_pool_userdata_get(&user_data, USER_DATA_KEY, s->process->pool);
    if (user_data == NULL) {
        apr_pool_userdata_set((const void *)(1), USER_DATA_KEY, apr_pool_cleanup_null, s->process->pool);
        return OK;
    }

    apr_status_t rv = create_shm(s, p);
    if(rv != APR_SUCCESS) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    rv = ap_global_mutex_create(&lock, NULL, mutex_id, NULL, s, p, 0);

    apr_pool_cleanup_register(p, NULL, cleanup_shm, apr_pool_cleanup_null);

    return OK;
}

static void initialize_child(apr_pool_t *p, server_rec *s)
{
    //DEBUGLOG("initialize_child is called");
    apr_status_t status;

    if (!shm) {
        DEBUGLOG("shm is null in initialize_child");
        return;
    }

    const char *lock_filename = apr_global_mutex_lockfile(lock);
    status = apr_global_mutex_child_init(&lock, lock_filename, p);
    if (status != APR_SUCCESS) {
        log_and_cleanup("failed to create lock (lock)", status, s);
        return;
    }
}

static void register_hooks(apr_pool_t *p)
{
    // read_request should be called after mod_setenvif's one
    ap_hook_post_read_request(dosdetector_read_request,NULL,NULL,APR_HOOK_LAST);

    ap_hook_pre_config(dosdetector_pre_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_config(dosdetector_post_config, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_child_init(initialize_child, NULL, NULL, APR_HOOK_MIDDLE);
}

module AP_MODULE_DECLARE_DATA dosdetector_module = {
    STANDARD20_MODULE_STUFF,
    dosdetector_create_dir_config, /* create per-dir config structures */
    NULL,            /* merge  per-dir    config structures */
    NULL,            /* create per-server config structures */
    NULL,            /* merge  per-server config structures */
    dosdetector_cmds,        /* table of config file commands       */
    register_hooks
};
