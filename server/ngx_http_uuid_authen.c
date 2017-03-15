/*
 * Copyright (C) 2017 winshining https://github.com/winshining
 * Copyright (C) 2002-2017 Igor Sysoev
 * Copyright (C) 2011-2017 Nginx, Inc.
 */

#include "ngx_http_log_collection_module.h"

ngx_int_t
ngx_http_uuid_authen_shm_slab_init(ngx_shm_zone_t *shm_zone, void *data)
{
	size_t len;
	ngx_http_log_collection_loc_conf_t *conf;
	ngx_http_log_collection_loc_conf_t *oldconf;

	conf = (ngx_http_log_collection_loc_conf_t *) shm_zone->data;
	oldconf = (ngx_http_log_collection_loc_conf_t *) data;

	if (oldconf) {
		conf->uuid_authen_conf.sh = oldconf->uuid_authen_conf.sh;
		conf->uuid_authen_conf.shpool = oldconf->uuid_authen_conf.shpool;
		return NGX_OK;
	}

	conf->uuid_authen_conf.shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
	conf->uuid_authen_conf.sh = ngx_slab_alloc(conf->uuid_authen_conf.shpool,
			sizeof(ngx_http_uuid_authen_shm_slab_t));
	if (conf->uuid_authen_conf.sh == NULL) {
		return NGX_ERROR;
	}

	conf->uuid_authen_conf.shpool->data = conf->uuid_authen_conf.sh;

	/* initialize the red-black tree */
	ngx_rbtree_init(&conf->uuid_authen_conf.sh->rbtree, &conf->uuid_authen_conf.sh->sentinel,
			ngx_str_rbtree_insert_value);

	len = ngx_strlen(" in uuid authen slab \"\"") + shm_zone->shm.name.len;
	conf->uuid_authen_conf.shpool->log_ctx = ngx_slab_alloc(conf->uuid_authen_conf.shpool, len);
	if (conf->uuid_authen_conf.shpool->log_ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_sprintf(conf->uuid_authen_conf.shpool->log_ctx, " in uuid authen slab \"%V\"%Z",
			&shm_zone->shm.name);

	return NGX_OK;
}

char *
ngx_http_uuid_authen_create_shm_slab(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t		*value, *name;
	ngx_shm_zone_t	*shm_zone;
	ngx_http_log_collection_loc_conf_t *lclcf;

	lclcf = (ngx_http_log_collection_loc_conf_t *)conf;
	lclcf->uuid_authen_conf.authen_switch = 0;

	value = cf->args->elts;
	name = &value[1];

	lclcf->uuid_authen_conf.shm_size = ngx_parse_size(&value[2]);
	if (lclcf->uuid_authen_conf.shm_size == (size_t) NGX_ERROR
		|| lclcf->uuid_authen_conf.shm_size == 0)
	{
		return "invalid value";
	}

	if (lclcf->uuid_authen_conf.shm_size < 10 * (1 << 20)) {
		lclcf->uuid_authen_conf.shm_size = 10 * (1 << 20);
	}

	shm_zone = ngx_shared_memory_add(cf, name, lclcf->uuid_authen_conf.shm_size,
			&ngx_http_log_collection_module);

	if (shm_zone == NULL) {
		lclcf->uuid_authen_conf.shm_size = 0;
		return NGX_CONF_ERROR;
	}

	shm_zone->init = ngx_http_uuid_authen_shm_slab_init;
	shm_zone->data = &lclcf->uuid_authen_conf;

	lclcf->uuid_authen_conf.authen_switch = 1;

	return NGX_CONF_OK;
}

ngx_int_t
ngx_http_uuid_authen_handler(ngx_http_request_t *r, ngx_str_t *uuid)
{
	uint32_t		hash;
	size_t			len;
	ngx_int_t		rc;
	ngx_uint_t		i;
	ngx_list_part_t	*part;
	ngx_table_elt_t	*header;
	ngx_str_node_t	*node;
	ngx_http_uuid_authen_node_t			*new;
	ngx_http_log_collection_loc_conf_t	*conf;

	conf = ngx_http_get_module_loc_conf(r, ngx_http_log_collection_module);

	if (r == NULL || uuid == NULL) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	part = &r->headers_in.headers.part;
	header = part->elts;

	for (i = 0; /* void */; i++) {
		if (i >= part->nelts) {
			if (part->next == NULL) {
				break;
			}

			part = part->next;
			header = part->elts;
			i = 0;
		}

		if (header[i].hash == 0) {
			continue;
		}

		if (ngx_strncasecmp(header[i].key.data,	(u_char *) CLIENT_UUID_STRING,
			ngx_strlen(CLIENT_UUID_STRING)) == 0)
		{
			uuid->data = header[i].value.data;
			uuid->len = header[i].value.len;

			if (uuid->len != UUID_STRING_LENGTH
				|| uuid->data[8] != '-'
				|| uuid->data[13] != '-'
				|| uuid->data[18] != '-'
				|| uuid->data[23] != '-')
			{
				ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid UUID format: %V", uuid);
				return NGX_HTTP_FORBIDDEN;
			}

			break;
		}
	}

	if (uuid->len == 0) {
		/* uuid not found */
		return NGX_HTTP_BAD_REQUEST;
	}

	if (conf->uuid_authen_conf.authen_switch == 0) {
		return NGX_DECLINED;
	}

	hash = ngx_crc32_short(uuid->data, uuid->len);

	ngx_shmtx_lock(&conf->uuid_authen_conf.shpool->mutex);

	node = ngx_str_rbtree_lookup(&conf->uuid_authen_conf.sh->rbtree, uuid, hash);
	if (node) {
		if (r->pipeline) {
			ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "It is a pipelined request");

			rc = NGX_DECLINED;
		} else {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "An uuid \"%V\" exists", uuid);

			rc = NGX_HTTP_FORBIDDEN;
		}
	} else {
		/* insert the uuid into the rbtree */
		len = sizeof(ngx_str_node_t) + UUID_STRING_LENGTH - 1;
		new = ngx_slab_alloc_locked(conf->uuid_authen_conf.shpool, len);
		if (new == NULL) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
					"Allocation for the node of uuid \"%V\" failed", uuid);

			rc = NGX_HTTP_FORBIDDEN;
		} else {
			ngx_memcpy(new->data, uuid->data, UUID_STRING_LENGTH);
			new->str_node.node.key = hash;
			new->str_node.str.data = new->data;
			new->str_node.str.len = ngx_strlen(new->data);
			ngx_rbtree_insert(&conf->uuid_authen_conf.sh->rbtree, &new->str_node.node);

			rc = NGX_DECLINED;
		}
	}

	ngx_shmtx_unlock(&conf->uuid_authen_conf.shpool->mutex);

	return rc;
}

void
ngx_http_uuid_authen_expire(ngx_http_request_t *r, ngx_str_t *uuid)
{
	uint32_t		hash;
	ngx_str_node_t	*node;
	ngx_http_log_collection_loc_conf_t	*lclcf;

	if (r == NULL || uuid == NULL) {
		return;
	}

	if (lclcf->uuid_authen_conf.authen_switch) {
		lclcf = ngx_http_get_module_loc_conf(r, ngx_http_log_collection_module);

		ngx_shmtx_lock(&lclcf->uuid_authen_conf.shpool->mutex);

		hash = ngx_crc32_short(uuid->data, uuid->len);
		node = ngx_str_rbtree_lookup(&lclcf->uuid_authen_conf.sh->rbtree, uuid, hash);
		if (node) {
			ngx_rbtree_delete(&lclcf->uuid_authen_conf.sh->rbtree, &node->node);
			ngx_slab_free_locked(lclcf->uuid_authen_conf.shpool, (void *) node);
		}

		ngx_shmtx_unlock(&lclcf->uuid_authen_conf.shpool->mutex);
	}
}

