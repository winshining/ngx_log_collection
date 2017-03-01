/*
 * Copyright (C) 2016-2017 winshining https://github.com/winshining
 * Copyright (C) 2002-2017 Igor Sysoev
 * Copyright (C) 2011-2017 Nginx, Inc.
 */

#ifndef __NGX_HTTP_UUID_AUTHEN_H__
#define __NGX_HTTP_UUID_AUTHEN_H__

/* the data in ngx_str_t points to data,
 * force the node all locate in the shm
 */
typedef struct {
	ngx_str_node_t	str_node;
	u_char			data[1];
} ngx_http_uuid_authen_node_t;

typedef struct {
	ngx_rbtree_t		rbtree;
	ngx_rbtree_node_t	sentinel;
} ngx_http_uuid_authen_shm_slab_t;

typedef struct {
	ngx_flag_t						authen_switch;
	size_t							shm_size;

	/* located in the shared memory */
	ngx_slab_pool_t					*shpool;
	ngx_http_uuid_authen_shm_slab_t	*sh;
} ngx_http_uuid_authen_conf_t;

extern ngx_module_t ngx_http_log_collection_module;

ngx_int_t
ngx_http_uuid_authen_shm_slab_init(ngx_shm_zone_t *shm_zone, void *data);

ngx_int_t
ngx_http_uuid_authen_handler(ngx_http_request_t *r, ngx_str_t *uuid);

char *
ngx_http_uuid_authen_create_shm_slab(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

void
ngx_http_uuid_authen_expire(ngx_http_request_t *r, ngx_str_t *uuid);

#endif

