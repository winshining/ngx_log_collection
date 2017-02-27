/*
 * Copyright (C) 2016 hongzhidao https://github.com/hongzhidao
 * Copyright (C) 2016-2017 winshining https://github.com/winshining
 * Copyright (C) 2006-2008 Valery Kholodkov
 * Copyright (C) 2002-2017 Igor Sysoev
 * Copyright (C) 2011-2017 Nginx, Inc.
 */

#ifndef __NGX_HTTP_LOG_COLLECTION_MODULE_H__
#define __NGX_HTTP_LOG_COLLECTION_MODULE_H__

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include "ngx_http_uuid_authen.h"

#define CLIENT_UUID_STRING			"Client-UUID" /* user defined */
#define UUID_STRING_LENGTH			36

/*
 * Log collection configuration for specific location
 */
typedef struct ngx_http_log_collection_loc_conf_s {
	/* for uuid authentication */
	ngx_http_uuid_authen_conf_t uuid_authen_conf;

	/* for backend */
	ngx_str_t	url;
	ngx_http_complex_value_t *url_cv;

	ngx_flag_t	all_in_single_folder;
	ngx_flag_t	log_collection_switch;
	ngx_flag_t	log_content_decode;
	ngx_flag_t	log_content_purify;
	ngx_flag_t	redirect_to_backend;
	ngx_path_t	*store_path;
	ngx_str_t	store_map_to_uri;

	ngx_array_t	*field_templates; /* ngx_http_log_collection_field_template_t */
	ngx_flag_t	forward_args;

	off_t		max_file_size;
	size_t		max_request_body_size;
	size_t		upload_limit_rate;
} ngx_http_log_collection_loc_conf_t;

#endif

