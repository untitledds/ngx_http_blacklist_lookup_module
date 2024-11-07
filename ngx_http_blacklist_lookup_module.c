#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_inet.h>

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

static int explode(ngx_str_t ***arr_ptr, ngx_str_t *str, u_char delimiter)
{
    u_char *src = str->data, *end, *dst;
    ngx_str_t **arr;
    int size = 1, i;

    // Count the number of delimiters to determine the size of the array
    while ((end = (u_char *)ngx_strchr(src, delimiter)) != NULL) {
        ++size;
        src = end + 1;
    }

    // Allocate memory for the array of ngx_str_t pointers and the concatenated strings
    arr = ngx_alloc(size * sizeof(ngx_str_t *) + (str->len + 1) * sizeof(u_char), ngx_cycle->log);
    if (arr == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Memory allocation failed in explode");
        return -1; // Memory allocation failed
    }

    // Set the source pointer back to the beginning of the string
    src = str->data;
    // Calculate the starting point for the concatenated strings
    dst = (u_char *) arr + size * sizeof(ngx_str_t *);

    // Loop through the string and split it into parts
    for (i = 0; i < size; ++i) {
        if ((end = (u_char *)ngx_strchr(src, delimiter)) == NULL) {
            end = src + (str->len - (src - str->data)); // If no delimiter found, point to the end of the string
        }
        arr[i] = (ngx_str_t *) dst; // Set the current array element to the current position in the concatenated strings
        arr[i]->len = end - src; // Set the length of the current substring
        arr[i]->data = dst; // Set the data pointer of the current substring
        ngx_memcpy(dst, src, end - src); // Copy the substring to the concatenated strings
        dst += end - src; // Move the destination pointer to the next position
        *dst++ = '\0'; // Null-terminate the substring
        src = end + 1; // Move the source pointer to the next substring
    }

    *arr_ptr = arr; // Set the output array pointer

    return size; // Return the number of elements in the array
}

static int reverseIpv4(ngx_str_t *ip, ngx_str_t *reversedIp) {
    ngx_str_t **arr;
    int size, i;

    // Split the string by the '.' character
    size = explode(&arr, ip, '.');
    if (size < 0) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Failed to explode IP address");
        return -1;
    }

    // Clear reversedIp to avoid garbage in the result
    reversedIp->len = 0;

    // Form the reversed IP address
    for (i = size-1; i >= 0; i--) {
        // Copy the IP address part into reversedIp
        ngx_memcpy(reversedIp->data + reversedIp->len, arr[i]->data, arr[i]->len);
        reversedIp->len += arr[i]->len;

        // If it's not the last part, add a dot
        if (i != 0) {
            reversedIp->data[reversedIp->len] = '.';
            reversedIp->len += 1;
        }
    }

    // Free the memory allocated for arr
    ngx_pfree(ngx_cycle->pool, arr);

    return 0;
}

static int lookupAddr(ngx_http_request_t *r, ngx_str_t *ip_as_string, ngx_str_t *ipstr) {
    in_addr_t addr;
    struct in_addr inaddr;
    size_t buffer_size = NGX_INET_ADDRSTRLEN;

    // Преобразуем строку IP-адреса в in_addr_t
    addr = ngx_inet_addr(ip_as_string->data, ip_as_string->len);
    if (addr == INADDR_NONE) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid IP address: %V", ip_as_string);
        return 0;
    }

    // Преобразуем in_addr_t в строку
    inaddr.s_addr = addr;
    size_t result_len = ngx_inet_ntop(AF_INET, &inaddr, ipstr->data, buffer_size);
    if (result_len == (size_t)NGX_ERROR) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to convert IP address to string: %V", ip_as_string);
        return 0;
    }

    // Устанавливаем длину строки
    ipstr->len = result_len;

    return 1;
}

static int uceprotect_net(ngx_http_request_t *r, ngx_str_t *ip, ngx_str_t *reversedIp) {
    const char* blocklistHost = "dnsbl-1.uceprotect.net";

    ngx_str_t fullHostname;
    fullHostname.data = ngx_pcalloc(r->pool, 256);
    if (fullHostname.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed in uceprotect_net");
        return 0; // или другое действие в случае ошибки
    }

    // Исправленная строка
    u_char* temp = ngx_snprintf(fullHostname.data, 256, "%V.%s", reversedIp, blocklistHost);
    fullHostname.len = temp - fullHostname.data;

    ngx_str_t resolvedResultIp;
    resolvedResultIp.data = ngx_pcalloc(r->pool, INET6_ADDRSTRLEN);
    if (resolvedResultIp.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed in uceprotect_net");
        return 0; // или другое действие в случае ошибки
    }
    resolvedResultIp.len = INET6_ADDRSTRLEN;

    int resolvedResult = lookupAddr(r, &fullHostname, &resolvedResultIp);

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
    fullHostname.data = ngx_pcalloc(r->pool, 256);
    if (fullHostname.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed in blocklist_de");
        return 0; // или другое действие в случае ошибки
    }

    // Исправленная строка
    u_char* temp = ngx_snprintf(fullHostname.data, 256, "%V.%s", reversedIp, blocklistHost);
    fullHostname.len = temp - fullHostname.data;

    ngx_str_t resolvedResultIp;
    resolvedResultIp.data = ngx_pcalloc(r->pool, INET6_ADDRSTRLEN);
    if (resolvedResultIp.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed in blocklist_de");
        return 0; // или другое действие в случае ошибки
    }
    resolvedResultIp.len = INET6_ADDRSTRLEN;

    int resolvedResult = lookupAddr(r, &fullHostname, &resolvedResultIp);

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
    fullHostname.data = ngx_pcalloc(r->pool, 256);
    if (fullHostname.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed in projecthoneypot_org");
        return 0; // или другое действие в случае ошибки
    }

    // Исправленная строка
    u_char* temp = ngx_snprintf(fullHostname.data, 256, "%V.%V.%s", honeyPotAccessKey, reversedIp, blocklistHost);
    fullHostname.len = temp - fullHostname.data;

    ngx_str_t resolvedResultIp;
    resolvedResultIp.data = ngx_pcalloc(r->pool, INET6_ADDRSTRLEN);
    if (resolvedResultIp.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed in projecthoneypot_org");
        return 0; // или другое действие в случае ошибки
    }
    resolvedResultIp.len = INET6_ADDRSTRLEN;

    int resolvedResult = lookupAddr(r, &fullHostname, &resolvedResultIp);

    if (resolvedResult > 0) {
        ngx_str_t **arr;
        int size;
        size = explode(&arr, &resolvedResultIp, '.');
        if (size > 3 && ngx_atoi(arr[3]->data, arr[3]->len) >= 3) {
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
    if (shpool == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Shared memory address is NULL in ngx_http_blacklist_lookup_init_shm_zone");
        return NGX_ERROR;
    }

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    tree = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_t));
    if (tree == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Memory allocation failed in ngx_http_blacklist_lookup_init_shm_zone");
        return NGX_ERROR;
    }

    sentinel = ngx_slab_alloc(shpool, sizeof(ngx_rbtree_node_t));
    if (sentinel == NULL) {
        ngx_log_error(NGX_LOG_ERR, ngx_cycle->log, 0, "Memory allocation failed in ngx_http_blacklist_lookup_init_shm_zone");
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
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Starting ngx_http_blacklist_lookup_handler");
    
    ngx_http_blacklist_lookup_loc_conf_t *alcf;
    ngx_slab_pool_t *shpool;
    ngx_http_blacklist_lookup_value_node_t *found, *new_node;
    uint32_t hash;

    // Подготовка для записи IP-адреса клиента
    ngx_str_t client_ip;
    client_ip.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    if (client_ip.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed for client IP");
        return NGX_ERROR;
    }
    client_ip.len = INET6_ADDRSTRLEN;

    // Проверка наличия подключения и sockaddr
    if (r->connection == NULL || r->connection->sockaddr == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Connection or sockaddr is NULL");
        return NGX_ERROR;
    }

    // Получаем клиентский IP-адрес
    if (r->connection->sockaddr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &(((struct sockaddr_in *)(r->connection->sockaddr))->sin_addr.s_addr), (char *)client_ip.data, client_ip.len);
    } else if (r->connection->sockaddr->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)(r->connection->sockaddr))->sin6_addr), (char *)client_ip.data, client_ip.len);
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Unsupported address family");
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Client IP: %V", &client_ip);

    // Получение конфигурации модуля
    alcf = ngx_http_get_module_loc_conf(r, ngx_http_blacklist_lookup_module);

    if (!alcf->enable) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Blacklist lookup is disabled");
        return NGX_OK;
    }

    // Установка флагов
    ngx_http_blacklist_lookup_verbose = alcf->verbose;
    ngx_str_t honeyPotAccessKey = alcf->honeyPotAccessKey;

    // Подготовка для хранения IP как строки
    ngx_str_t ip_as_char;
    ip_as_char.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    if (ip_as_char.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed for ip_as_char");
        return NGX_ERROR;
    }
    ngx_memcpy(ip_as_char.data, client_ip.data, client_ip.len);
    ip_as_char.len = client_ip.len;

    // Получаем строку адреса
    ngx_str_t ip_as_string = r->connection->addr_text;
    hash = ngx_crc32_long(ip_as_string.data, ip_as_string.len);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Calculated hash for IP %V", &ip_as_string);

    // Доступ к общей памяти
    shpool = (ngx_slab_pool_t *)ngx_http_blacklist_lookup_shm_zone->shm.addr;
    if (shpool == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Shared memory pool is not initialized");
        return NGX_ERROR;
    }

    // Проверяем кэш
    ngx_shmtx_lock(&shpool->mutex);
    found = (ngx_http_blacklist_lookup_value_node_t *)ngx_str_rbtree_lookup(ngx_http_blacklist_lookup_rbtree, &ip_as_string, hash);
    ngx_shmtx_unlock(&shpool->mutex);

    int expired = 0;
    int bad = 0;
    
    if (found) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Found IP %V in cache", &ip_as_string);
        
        if (ngx_time() > found->expire) {
            expired = 1;
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "IP %V is expired", &ip_as_string);
        }

        if (found->result >= alcf->hits) {
            bad = 1;
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "IP %V is bad", &ip_as_string);
        }

        // Удаляем истекшие IP из кеша
        if (expired == 1) {
            ngx_shmtx_lock(&shpool->mutex);
            ngx_rbtree_delete(ngx_http_blacklist_lookup_rbtree, &found->sn.node);
            ngx_slab_free_locked(shpool, found);
            ngx_shmtx_unlock(&shpool->mutex);
            ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Deleted expired IP %V from cache", &ip_as_string);
        }

        // Возвращаем ошибку для "плохих" IP
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

    // Обработка нового IP, если он не найдён в кеше
    ngx_str_t reversedIp;
    reversedIp.data = ngx_palloc(r->pool, INET6_ADDRSTRLEN);
    if (reversedIp.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed for reversedIp");
        return NGX_ERROR;
    }
    reversedIp.len = INET6_ADDRSTRLEN;
    
    if (reverseIpv4(&ip_as_char, &reversedIp) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to reverse IP address");
        return NGX_ERROR;
    }
    
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Reversed IP address: %V", &reversedIp);

    // Проверка различных черных списков
    int total = 0;
    if (alcf->uceprotect_net) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Checking uceprotect.net for IP %V", &ip_as_char);
        total += uceprotect_net(r, &ip_as_char, &reversedIp);
    } else {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Skipping uceprotect.net check for IP %V", &ip_as_char);
    }

    if (alcf->blocklist_de) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Checking blocklist.de for IP %V", &ip_as_char);
        total += blocklist_de(r, &ip_as_char, &reversedIp);
    } else {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Skipping blocklist.de check for IP %V", &ip_as_char);
    }

    if (alcf->projecthoneypot_org) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Checking projecthoneypot.org for IP %V", &ip_as_char);
        total += projecthoneypot_org(r, &ip_as_char, &reversedIp, &honeyPotAccessKey);
    } else {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Skipping projecthoneypot.org check for IP %V", &ip_as_char);
    }

    // Удаление устаревших записей перед вставкой новой
    ngx_shmtx_lock(&shpool->mutex);
    ngx_http_blacklist_lookup_delete_expired(shpool, ngx_http_blacklist_lookup_rbtree->root, ngx_http_blacklist_lookup_rbtree->sentinel);
    
    new_node = ngx_slab_alloc_locked(shpool, sizeof(ngx_http_blacklist_lookup_value_node_t));
    if (new_node == NULL) {
        ngx_shmtx_unlock(&shpool->mutex);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Memory allocation failed in ngx_http_blacklist_lookup_handler");
        return NGX_ERROR;
    }

    new_node->sn.node.key = hash;
    new_node->sn.str.len = ip_as_string.len;
    new_node->sn.str.data = ip_as_string.data;
    new_node->result = total;
    new_node->expire = ngx_time() + 900; // Устанавливаем время жизни записи

    ngx_rbtree_insert(ngx_http_blacklist_lookup_rbtree, &new_node->sn.node);
    ngx_shmtx_unlock(&shpool->mutex);
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Inserted IP %V into cache with result %d", &ip_as_string, total);

    // Если IP присутствует в черном списке, возвращаем сообщение
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
        r->headers_out.content_type.data = (u_char *)"text/html; charset=utf8";

        b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
        if (b == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        out.buf = b;
        out.next = NULL;

        b->pos = message;
        b->last = message + ngx_strlen(message);
        b->memory = 1; // buf allocated in pool
        b->last_buf = 1;

        r->headers_out.status = NGX_HTTP_FORBIDDEN;
        r->headers_out.content_length_n = ngx_strlen(message);
        ngx_http_send_header(r);

        return ngx_http_output_filter(r, &out);
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "Ending ngx_http_blacklist_lookup_handler");
    return NGX_OK;
}

static void *ngx_http_blacklist_lookup_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_blacklist_lookup_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_blacklist_lookup_loc_conf_t));
    if (conf == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Memory allocation failed in ngx_http_blacklist_lookup_create_loc_conf");
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
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to push handler in ngx_http_blacklist_lookup_init");
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
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "Failed to add shared memory zone in ngx_http_blacklist_lookup_init");
        return NGX_ERROR;
    }
    ngx_http_blacklist_lookup_shm_zone->init = ngx_http_blacklist_lookup_init_shm_zone;

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "ngx_http_blacklist_lookup_module loaded successfully");

    return NGX_OK;
}
