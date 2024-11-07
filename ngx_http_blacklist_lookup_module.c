/**
* @file ngx_http_blacklist_lookup_module.c
* @author Oleg Neumyvakin <oneumyvakin@gmail.com>
* @date Sun Mar 24 16:46:01 2013
*
* @brief Simple HTTP DNS blacklist module for Nginx.
*
* @section LICENSE
*
* Copyright (C) 2013 by Oleg Neumyvakin <oneumyvakin@gmail.com>
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
* @section TODO
* - replace internal resolver with ngx_resolver		- DONE
* - make uceprotect.net and blocklist.de optional	- DONE
*/
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_flag_t      enable;
    ngx_flag_t      verbose;
    ngx_uint_t      hits;
    ngx_flag_t      projecthoneypot_org;
    ngx_flag_t      blocklist_de;
    ngx_flag_t      uceprotect_net;
    ngx_str_t       honeyPotAccessKey;
    ngx_str_t       lang;
} ngx_http_blacklist_lookup_loc_conf_t;

typedef struct {
    ngx_str_node_t  sn;
    time_t          expire;
    ngx_uint_t      result;
} ngx_http_blacklist_lookup_value_node_t;

typedef struct {
    ngx_rbtree_t    *tree;
    time_t          expire;
} ngx_http_blacklist_lookup_shm_data_t;

static ngx_int_t ngx_http_blacklist_lookup_init(ngx_conf_t *cf);
static void *ngx_http_blacklist_lookup_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_blacklist_lookup_init_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_blacklist_lookup_handler(ngx_http_request_t *r);

static int ngx_http_blacklist_lookup_verbose; /* verbose flag */

static ngx_uint_t ngx_http_blacklist_lookup_shm_size;
static ngx_shm_zone_t * ngx_http_blacklist_lookup_shm_zone;
static ngx_rbtree_t * ngx_http_blacklist_lookup_rbtree;

static ngx_command_t ngx_http_blacklist_lookup_commands[] = {
    { ngx_string("blacklist_lookup"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, enable), NULL },
    { ngx_string("blacklist_lookup_verbose"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, verbose), NULL },
    { ngx_string("blacklist_lookup_hits"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_num_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, hits), NULL },
    { ngx_string("blacklist_lookup_bounce"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, lang), NULL },
    { ngx_string("blacklist_lookup_blocklist_de"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, blocklist_de), NULL },
    { ngx_string("blacklist_lookup_uceprotect_net"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, uceprotect_net), NULL },
    { ngx_string("blacklist_lookup_projecthoneypot_org"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG, ngx_conf_set_flag_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, projecthoneypot_org), NULL },
    { ngx_string("blacklist_lookup_honeyPotAccessKey"), NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1, ngx_conf_set_str_slot, NGX_HTTP_LOC_CONF_OFFSET, offsetof(ngx_http_blacklist_lookup_loc_conf_t, honeyPotAccessKey), NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_blacklist_lookup_module_ctx = {
    NULL, ngx_http_blacklist_lookup_init,
    NULL, NULL,
    NULL, NULL,
    ngx_http_blacklist_lookup_create_loc_conf, ngx_http_blacklist_lookup_init_loc_conf
};

ngx_module_t ngx_http_blacklist_lookup_module = {
    NGX_MODULE_V1,
    &ngx_http_blacklist_lookup_module_ctx,
    ngx_http_blacklist_lookup_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static int explode(ngx_str_t **arr_ptr, ngx_str_t *str, u_char delimiter) {
    ngx_str_t *src = str, *dst;
    ngx_str_t **arr;
    int size = 1, i;
    char *end;

    // Count the number of delimiters to determine the size of the array
    while ((end = ngx_strchr(src->data, delimiter)) != NULL) {
        ++size;
        src->data = end + 1; // Update src to point to the next character after the delimiter
        src->len = src->len - (end - src->data); // Update the length of src
    }

    // Allocate memory for the array of ngx_str_t pointers
    arr = ngx_palloc(ngx_cycle->pool, size * sizeof(ngx_str_t *));
    if (arr == NULL) {
        return -1; // Handle memory allocation failure
    }

    // Reset src to the beginning of the string
    src = str;

    // Fill the array with the split strings
    for (i = 0; i < size; ++i) {
        if ((end = ngx_strchr(src->data, delimiter)) != NULL) {
            arr[i] = ngx_palloc(ngx_cycle->pool, sizeof(ngx_str_t));
            arr[i]->data = src->data;
            arr[i]->len = end - src->data;
            src->data = end + 1;
            src->len = src->len - (end - src->data);
        } else {
            // Last segment
            arr[i] = ngx_palloc(ngx_cycle->pool, sizeof(ngx_str_t));
            arr[i]->data = src->data;
            arr[i]->len = src->len;
        }
    }

    *arr_ptr = arr;

    return size;
}

static int reverseIpv4(ngx_str_t *ip, ngx_str_t *reversedIp) {
    ngx_str_t **arr, *str = ip;
    int size, i;

    size = explode(&arr, str, '.');

    for (i = size-1; i >= 0; i--) {
        ngx_strncat(reversedIp, arr[i], arr[i]->len);
        if (i != 0) {
            ngx_strncat(reversedIp, ".", 1);
        }
    }

    ngx_pfree(ngx_cycle->pool, arr);
    return 0;
}

static int lookupAddr(ngx_str_t *ip_as_string, ngx_str_t *ipstr) {
    int status;
    struct addrinfo hints;
    struct addrinfo *servinfo, *p;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((status = getaddrinfo(ip_as_string->data, NULL, &hints, &servinfo)) != 0) {
        if (ngx_http_blacklist_lookup_verbose) {
            ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "getaddrinfo: %V %s", ip_as_string, gai_strerror(status));
        }
        return 0;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        void *addr;
        char *ipver;

        if (p->ai_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
            ngx_snprintf(ipstr->data, ipstr->len + 5, "%s", inet_ntoa(ipv4->sin_addr));
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }
    }

    freeaddrinfo(servinfo);
    return 1;
}

static int uceprotect_net(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *reversedIp) {
    const char* blocklistHost = "dnsbl-1.uceprotect.net";

    ngx_str_t fullHostname;
    fullHostname.data = ngx_palloc(r->pool, 256);
    fullHostname.len = ngx_snprintf(fullHostname.data, 256, "%V.%s", reversedIp, blocklistHost);

    ngx_str_t resolvedResultIp;
    resolvedResultIp.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    resolvedResultIp.len = INET6_ADDRSTRLEN;

    int resolvedResult = lookupAddr(&fullHostname, &resolvedResultIp);

    if (resolvedResult > 0) {
        if (ngx_http_blacklist_lookup_verbose) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "IP %V requested as %V resolved in black list as %V", ip, &fullHostname, &resolvedResultIp);
        }
        return 1;
    }

    return 0;
}

static int blocklist_de(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *reversedIp) {
    const char* blocklistHost = "bl.blocklist.de";

    ngx_str_t fullHostname;
    fullHostname.data = ngx_palloc(r->pool, 256);
    fullHostname.len = ngx_snprintf(fullHostname.data, 256, "%V.%s", reversedIp, blocklistHost);

    ngx_str_t resolvedResultIp;
    resolvedResultIp.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    resolvedResultIp.len = INET6_ADDRSTRLEN;

    int resolvedResult = lookupAddr(&fullHostname, &resolvedResultIp);

    if (resolvedResult > 0) {
        if (ngx_http_blacklist_lookup_verbose) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "IP %V requested as %V resolved in black list as %V", ip, &fullHostname, &resolvedResultIp);
        }
        return 1;
    }

    return 0;
}

static int projecthoneypot_org(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *reversedIp, ngx_str_t *honeyPotAccessKey) {
    ngx_str_t nokey = ngx_string("nokey");
    if (ngx_strcmp(honeyPotAccessKey->data, nokey.data) == 0) {
        return 0;
    }

    const char* blocklistHost = "dnsbl.httpbl.org";

    ngx_str_t fullHostname;
    fullHostname.data = ngx_palloc(r->pool, 256);
    fullHostname.len = ngx_snprintf(fullHostname.data, 256, "%V.%V.%s", honeyPotAccessKey, reversedIp, blocklistHost);

    ngx_str_t resolvedResultIp;
    resolvedResultIp.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    resolvedResultIp.len = INET6_ADDRSTRLEN;

    int resolvedResult = lookupAddr(&fullHostname, &resolvedResultIp);

    if (resolvedResult > 0) {
        ngx_str_t **arr;
        int size;
        size = explode(&arr, &resolvedResultIp, '.');
        if (ngx_atoi(arr[3]->data, arr[3]->len) >= 3) {
            if (ngx_http_blacklist_lookup_verbose) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "IP %V requested as %V resolved in black list as %V", ip, &fullHostname, &resolvedResultIp);
            }
            return 1;
        }
    }

    return 0;
}

static ngx_int_t ngx_http_blacklist_lookup_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data) {
    ngx_slab_pool_t *shpool;
    ngx_rbtree_t *tree;
    ngx_rbtree_node_t *sentinel;

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    tree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (tree == NULL) {
        ngx_slab_free(shpool, tree);
        return NGX_ERROR;
    }

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        ngx_slab_free(shpool, sentinel);
        return NGX_ERROR;
    }

    ngx_rbtree_sentinel_init(sentinel);
    ngx_rbtree_init(tree, sentinel, ngx_str_rbtree_insert_value);
    shm_zone->data = tree;
    ngx_http_blacklist_lookup_rbtree = tree;

    return NGX_OK;
}

static int get_bounce_message(ngx_str_t *lang, u_char *message, ngx_str_t *ip_as_char) {
    if (ngx_strcmp(lang->data, "ru") == 0) {
        ngx_snprintf(message, 1024, "<html><head><title>Доступ к сайту заблокирован для Вашего IP %V</title><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" /></head><body bgcolor=\"white\"><center><h1>Доступ к сайту заблокирован, т.к. Ваш IP %V находится в черном списке</h1></center><hr><p>Вы можете проверить свой IP адрес здесь <a href=\"http://www.debouncer.com/blacklistlookup\">http://www.debouncer.com/blacklistlookup</a></p><center>nginx</center></body></html>", ip_as_char, ip_as_char);
        return 0;
    }
    ngx_snprintf(message, 1024, "<html><head><title>Access to web site has been blocked for your IP %V</title><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\" /></head><body bgcolor=\"white\"><center><h1>Access to web site has been blocked for you, because your IP %V has been found in black list</h1></center><hr><p>You can check your IP address here <a href=\"http://www.debouncer.com/blacklistlookup\">http://www.debouncer.com/blacklistlookup</a></p><center>nginx</center></body></html>", ip_as_char, ip_as_char);
    return 0;
}

static ngx_http_blacklist_lookup_value_node_t *ngx_http_blacklist_lookup_delete_expired(ngx_slab_pool_t *shpool, ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel) {
    ngx_http_blacklist_lookup_value_node_t *cur_node;
    ngx_http_blacklist_lookup_value_node_t *found_node = NULL;
    ngx_http_blacklist_lookup_value_node_t *tmp_node;

    if (node == sentinel) {
        return NULL;
    }

    if (node->left != sentinel) {
        tmp_node = ngx_http_blacklist_lookup_delete_expired(shpool, node->left, sentinel);
        if (tmp_node) {
            found_node = tmp_node;
        }
    }

    if (node->right != sentinel) {
        tmp_node = ngx_http_blacklist_lookup_delete_expired(shpool, node->right, sentinel);
        if (tmp_node) {
            found_node = tmp_node;
        }
    }

    cur_node = (ngx_http_blacklist_lookup_value_node_t *) node;
    if (ngx_time() > cur_node->expire) {
        ngx_rbtree_delete(ngx_http_blacklist_lookup_rbtree, node);
        ngx_slab_free_locked(shpool, node);
    }

    return found_node;
}

static ngx_int_t ngx_http_blacklist_lookup_handler(ngx_http_request_t *r) {
    ngx_http_blacklist_lookup_loc_conf_t *alcf;
    ngx_slab_pool_t *shpool;
    ngx_http_blacklist_lookup_value_node_t *found, *new_node;
    uint32_t hash;

    alcf = ngx_http_get_module_loc_conf(r, ngx_http_blacklist_lookup_module);

    if (!alcf->enable) {
        return NGX_OK;
    }

    ngx_http_blacklist_lookup_verbose = alcf->verbose;
    ngx_str_t honeyPotAccessKey = alcf->honeyPotAccessKey;

    ngx_str_t ip_as_char;
    ip_as_char.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    ip_as_char.len = INET6_ADDRSTRLEN;

    switch (r->connection->sockaddr->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *) (r->connection->sockaddr))->sin_addr.s_addr), ip_as_char.data, ip_as_char.len);
            break;
        case AF_INET6:
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "IPv6 is not supported in blacklist_lookup");
            return NGX_OK;
    }

    ngx_str_t ip_as_string = r->connection->addr_text;
    hash = ngx_crc32_long(ip_as_string.data, ip_as_string.len);

    shpool = (ngx_slab_pool_t *) ngx_http_blacklist_lookup_shm_zone->shm.addr;
    ngx_shmtx_lock(&shpool->mutex);
    found = (ngx_http_blacklist_lookup_value_node_t *) ngx_str_rbtree_lookup(ngx_http_blacklist_lookup_rbtree, &ip_as_string, hash);
    ngx_shmtx_unlock(&shpool->mutex);

    int expired = 0;
    int bad = 0;
    if (found) {
        if (ngx_time() > found->expire) {
            expired = 1;
        }

        if (found->result >= alcf->hits) {
            bad = 1;
        }

        if (expired == 1) {
            ngx_shmtx_lock(&shpool->mutex);
            ngx_rbtree_delete(ngx_http_blacklist_lookup_rbtree, &found->sn.node);
            ngx_slab_free_locked(shpool, found);
            ngx_shmtx_unlock(&shpool->mutex);
        }

        if (bad == 1) {
            if (ngx_http_blacklist_lookup_verbose) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Skip check because bad IP");
            }
            return NGX_HTTP_FORBIDDEN;
        }

        if (ngx_http_blacklist_lookup_verbose) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Skip check because good IP");
        }

        return NGX_OK;
    }

    ngx_str_t reversedIp;
    reversedIp.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    reversedIp.len = INET6_ADDRSTRLEN;
    reverseIpv4(&ip_as_char, &reversedIp);

    int total = 0;
    if (alcf->uceprotect_net) {
        total += uceprotect_net(r, &ip_as_char, &reversedIp);
    }
    if (alcf->blocklist_de) {
        total += blocklist_de(r, &ip_as_char, &reversedIp);
    }
    if (alcf->projecthoneypot_org) {
        total += projecthoneypot_org(r, &ip_as_char, &reversedIp, &honeyPotAccessKey);
    }

    ngx_shmtx_lock(&shpool->mutex);
    ngx_http_blacklist_lookup_delete_expired(shpool, ngx_http_blacklist_lookup_rbtree->root, ngx_http_blacklist_lookup_rbtree->sentinel);
    new_node = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_blacklist_lookup_value_node_t));
    if (new_node == NULL) {
        return NGX_ERROR;
    }
    new_node->sn.node.key = hash;
    new_node->sn.str.len = ip_as_string.len;
    new_node->sn.str.data = ip_as_string.data;
    new_node->result = total;
    new_node->expire = ngx_time() + 900;

    ngx_rbtree_insert(ngx_http_blacklist_lookup_rbtree, &new_node->sn.node);

    ngx_shmtx_unlock(&shpool->mutex);

    if (total > 0) {
        ngx_str_t lang = alcf->lang;

        u_char message[1024] = "";
        int gbm_res = get_bounce_message(&lang, message, &ip_as_char);
        if (gbm_res > 0) {
            return NGX_HTTP_FORBIDDEN;
        }

        ngx_buf_t *b;
        ngx_chain_t out;

        r->headers_out.content_type.len = sizeof("text/html; charset=utf8") - 1;
        r->headers_out.content_type.data = (u_char *) "text/html; charset=utf8";

        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

        out.buf = b;
        out.next = NULL;

        b->pos = message;
        b->last = message + sizeof(message);
        b->memory = 1;
        b->last_buf = 1;

        r->headers_out.status = NGX_HTTP_FORBIDDEN;
        r->headers_out.content_length_n = sizeof(message);
        ngx_http_send_header(r);

        return ngx_http_output_filter(r, &out);
    }

    return NGX_OK;
}

static void *ngx_http_blacklist_lookup_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_blacklist_lookup_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_blacklist_lookup_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->enable = NGX_CONF_UNSET;
    conf->verbose = NGX_CONF_UNSET;
    conf->hits = NGX_CONF_UNSET_UINT;
    conf->projecthoneypot_org = NGX_CONF_UNSET;
    conf->blocklist_de = NGX_CONF_UNSET;
    conf->uceprotect_net = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_blacklist_lookup_init_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_blacklist_lookup_loc_conf_t *prev = parent;
    ngx_http_blacklist_lookup_loc_conf_t *conf = child;
    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->verbose, prev->verbose, 0);
    ngx_conf_merge_value(conf->projecthoneypot_org, prev->projecthoneypot_org, 0);
    ngx_conf_merge_value(conf->blocklist_de, prev->blocklist_de, 0);
    ngx_conf_merge_value(conf->uceprotect_net, prev->uceprotect_net, 0);
    ngx_conf_merge_uint_value(conf->hits, prev->hits, 1);
    ngx_conf_merge_str_value(conf->honeyPotAccessKey, prev->honeyPotAccessKey, "nokey");
    ngx_conf_merge_str_value(conf->lang, prev->lang, "en");

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_blacklist_lookup_init(ngx_conf_t *cf) {
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cscf;

    cscf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cscf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_blacklist_lookup_handler;

    ngx_str_t *shm_name;
    shm_name = ngx_palloc(cf->pool, sizeof *shm_name);
    shm_name->len = sizeof("blacklist_lookup") - 1;
    shm_name->data = (unsigned char *) "blacklist_lookup";

    if (ngx_http_blacklist_lookup_shm_size == 0) {
        ngx_http_blacklist_lookup_shm_size = 8 * ngx_pagesize;
    }

    ngx_http_blacklist_lookup_shm_zone = ngx_shared_memory_add(cf, shm_name, ngx_http_blacklist_lookup_shm_size, &ngx_http_blacklist_lookup_module);
    if (ngx_http_blacklist_lookup_shm_zone == NULL) {
        return NGX_ERROR;
    }
    ngx_http_blacklist_lookup_shm_zone->init = ngx_http_blacklist_lookup_init_shm_zone;

    return NGX_OK;
}
