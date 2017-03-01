/*
 * Copyright (C) 2016 hongzhidao https://github.com/hongzhidao
 * Copyright (C) 2016-2017 winshining https://github.com/winshining
 * Copyright (C) 2006-2008 Valery Kholodkov
 * Copyright (C) 2002-2017 Igor Sysoev
 * Copyright (C) 2011-2017 Nginx, Inc.
 */

#include <nginx.h>
#include "ngx_http_log_collection_module.h"

#define IP_STRING_MAX_LENGTH		15
#define CONTENT_TYPE_VALUE_STRING	"application/x-www-form-urlencoded"
/*
 * Information about MIME refers to:
 * http://stackoverflow.com/questions/4007969/application-x-www-form-urlencoded-or-multipart-form-data
 */

#define OUTPUT_STRING_DONE				"Done."
#define OUTPUT_STRING_CONTENT_NEEDED	"Content needed."
#define OUTPUT_STRING_CONTENT_LENGTH	"Content length"

#define MAX_NUMBER_STRING				"18446744073709551616"
#define FILE_POSTFIX_FORMAT				"1970_01_01_00_00_00"

#define NGX_LOG_COLLECTION_MALFORMED	-1
#define NGX_LOG_COLLECTION_NOMEM		-2
#define NGX_LOG_COLLECTION_IOERROR		-3
#define NGX_LOG_COLLECTION_TOOLARGE		-4
#define NGX_LOG_COLLECTION_SCRIPTERROR	-5
#define NGX_LOG_COLLECTION_BADPROTOCOL	-6

typedef enum {
	log_collection_state_header,
	log_collection_state_data,
	log_collection_state_finish
} ngx_http_log_collection_state_t;

typedef enum {
	log_collection_form_name,
	log_collection_form_value
} ngx_http_log_collection_form_t;

/*
 * Log collection cleanup record
 */
typedef struct ngx_http_log_collection_cleanup_s {
	ngx_fd_t				fd;
	u_char					*filename;
	ngx_http_headers_out_t	*headers_out;
	ngx_log_t				*log;
	unsigned int			aborted:1;
} ngx_http_log_collection_cleanup_t;

/*
 * Template for a field to generate in output form
 */
typedef struct {
    ngx_table_elt_t         value;
    ngx_array_t             *field_lengths;
    ngx_array_t             *field_values;
    ngx_array_t             *value_lengths;
    ngx_array_t             *value_values;
} ngx_http_log_collection_field_template_t;

struct ngx_http_log_collection_ctx_s;

typedef ngx_int_t (*ngx_http_log_collection_process_buffer_handler_pt)
		(struct ngx_http_log_collection_ctx_s *ctx, u_char *, size_t);

typedef struct ngx_http_log_collection_decode_output_buffer_data_s {
	unsigned int	need:2;
	ngx_pool_t		*pool;
	ngx_http_log_collection_process_buffer_handler_pt buffer_handler;
	size_t			decoded_length;
	u_char			left[1];
} ngx_http_log_collection_decode_output_buffer_data_t;

typedef struct ngx_http_log_collection_backend_data_s {
	/* for backend */
	ngx_chain_t				*field_name_chain;
	ngx_chain_t				**next;
	ngx_chain_t				*current;
	ngx_str_t				field_name;
	ngx_str_t				form_name;
	ngx_str_t				text_len;
	off_t					text_len_n;
	ngx_str_t				file_loc;
	ngx_chain_t				*chain;
	ngx_chain_t				*last;
} ngx_http_log_collection_backend_data_t;

typedef ngx_int_t (*ngx_http_log_collection_process_output_buffer_handler_pt)
		(struct ngx_http_log_collection_ctx_s *ctx, u_char **, u_char **);

typedef ngx_int_t (*ngx_http_log_collection_decode_output_buffer_handler_pt)
		(struct ngx_http_log_collection_ctx_s *ctx, u_char **, u_char **);

typedef struct ngx_http_log_collection_process_request_body_s {
	ngx_http_log_collection_form_t	form_state;
	ngx_flag_t						form_name_flag;
	u_char							*last_form_name_pos;
	u_char							*last_form_value_pos;

	ngx_http_log_collection_process_output_buffer_handler_pt process_output_buffer_handler;
	ngx_http_log_collection_decode_output_buffer_handler_pt decode_output_buffer_handler;

	unsigned int					log_content_purify:1;
	unsigned int					log_content_decode:1;

	void							*decode_output_buffer_handler_data;
} ngx_http_log_collection_process_request_body_data_t;

typedef ngx_int_t (*ngx_http_log_collection_process_request_body_handler_pt)
		(struct ngx_http_log_collection_ctx_s *ctx, u_char *, u_char *);

typedef ngx_int_t (*ngx_http_log_collection_backend_handler_pt)
		(ngx_http_request_t *r);

/*
 * Log collection module context
 */
typedef struct ngx_http_log_collection_ctx_s {
	ngx_http_log_collection_state_t	state;
	ngx_http_log_collection_process_request_body_handler_pt process_handler;
	void						*process_handler_data;

	ngx_file_t					output_file;
	ngx_http_request_t			*request;
	ngx_log_t					*log;
	ngx_pool_cleanup_t			*cln;

	size_t						body_length;
	size_t						written_length;
	size_t						upload_limit_rate;
	ssize_t						received;

	u_char						*output_buffer;
	off_t						output_buffer_len;

	ngx_str_t					client_uuid;
	ngx_int_t					output_status;

	ngx_http_log_collection_backend_handler_pt backend_handler;
	void						*backend_handler_data; /* for backend_handler */
	unsigned int				redirect_to_backend:1;
} ngx_http_log_collection_ctx_t;

/*
 * If store path not specified, use this one
 */
static ngx_path_init_t ngx_http_log_collection_temp_path = {
	ngx_string(NGX_HTTP_CLIENT_TEMP_PATH), { 0, 0, 0 }
};

static ngx_int_t ngx_http_log_collection_process_request_body(ngx_http_request_t *r, ngx_chain_t *body);
static ngx_int_t ngx_http_log_collection_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in);

static ngx_int_t ngx_http_log_collection_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in);

static char *ngx_http_log_collection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_log_collection_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_log_collection_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r);
static ngx_int_t ngx_http_log_collection_process_buffer_handler(ngx_http_log_collection_ctx_t *ctx,
	u_char *buffer, size_t len);
static ngx_int_t ngx_http_log_collection_get_variable(ngx_http_request_t *r,
	ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_log_collection_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_log_collection_add_variables(ngx_conf_t *cf);

static ngx_http_module_t ngx_http_log_collection_module_ctx = {
	ngx_http_log_collection_add_variables, /* preconfiguration */
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	ngx_http_log_collection_create_loc_conf,	/* create location configuration */
	ngx_http_log_collection_merge_loc_conf,		/* merge location configuration */
};

static ngx_command_t ngx_http_log_collection_commands[] = {
	{
		ngx_string("log_collection"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE12,
		ngx_http_log_collection,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},
	{
		ngx_string("all_in_single_folder"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, all_in_single_folder),
		NULL
	},
	{
		ngx_string("log_collection_store"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_path_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, store_path),
		NULL
	},
	{
		ngx_string("log_content_decode"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, log_content_decode),
		NULL
	},
	{
		ngx_string("log_content_purify"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_flag_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, log_content_purify),
		NULL
	},
	{
		ngx_string("store_map_to_uri"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, store_map_to_uri),
		NULL
	},
	{
		ngx_string("max_file_size"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, max_file_size),
		NULL
	},
	{
		ngx_string("upload_limit_rate"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, upload_limit_rate),
		NULL
	},
	{
		ngx_string("max_request_body_size"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
		ngx_conf_set_size_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, max_request_body_size),
		NULL
	},
	/*
	 * Specifies the field to set in altered response body
	 */
	{
		ngx_string("set_form_field"),
		NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_HTTP_LMT_CONF
		| NGX_HTTP_LIF_CONF | NGX_CONF_TAKE2,
		ngx_http_log_collection_set_form_field,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_log_collection_loc_conf_t, field_templates),
		NULL
	},
	{
		ngx_string("uuid_authen"),
		NGX_HTTP_LOC_CONF | NGX_CONF_TAKE2,
		ngx_http_uuid_authen_create_shm_slab,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL
	},

	ngx_null_command
};

static ngx_http_log_collection_backend_data_t backend_handler_data;

static ngx_http_variable_t ngx_http_log_collection_variables[] = {
	{
		ngx_string("field_name"),
		NULL,
		ngx_http_log_collection_get_variable,
		(uintptr_t) offsetof(ngx_http_log_collection_backend_data_t, field_name),
		NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
		0
	},
	{
		ngx_string("form_name"),
		NULL,
		ngx_http_log_collection_get_variable,
		(uintptr_t) offsetof(ngx_http_log_collection_backend_data_t, form_name),
		NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
		0
	},
	{
		ngx_string("text_len"),
		NULL,
		ngx_http_log_collection_get_variable,
		(uintptr_t) offsetof(ngx_http_log_collection_backend_data_t, text_len),
		NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
		0
	},
	{
		ngx_string("file_loc"),
		NULL,
		ngx_http_log_collection_get_variable,
		(uintptr_t) offsetof(ngx_http_log_collection_backend_data_t, file_loc),
		NGX_HTTP_VAR_CHANGEABLE | NGX_HTTP_VAR_NOCACHEABLE | NGX_HTTP_VAR_NOHASH,
		0
	},

	{ ngx_null_string, NULL, NULL, 0, 0, 0 }
};

ngx_module_t ngx_http_log_collection_module = {
	NGX_MODULE_V1,
	&ngx_http_log_collection_module_ctx,
	ngx_http_log_collection_commands,
	NGX_HTTP_MODULE,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NGX_MODULE_V1_PADDING
};

ngx_int_t
ngx_http_log_collection_request_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
#if defined nginx_version && nginx_version >= 1003009
	if (r->headers_in.chunked) {
		return NGX_LOG_COLLECTION_BADPROTOCOL;
	} else {
#endif
		return ngx_http_log_collection_request_body_length_filter(r, in);
#if defined nginx_version && nginx_version >= 1003009
	}
#endif
}

ngx_int_t
ngx_http_log_collection_request_body_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
	size_t						size;
	ngx_int_t					rc;
	ngx_buf_t					*b;
	ngx_chain_t					*cl, *tl, *out, **ll;
	ngx_http_request_body_t		*rb;

	rb = r->request_body;

	if (rb->rest == -1) {
		ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"Http request body content length filter");
		rb->rest = r->headers_in.content_length_n;
	}

	out = NULL;
	ll = &out;

	for (cl = in; cl; cl = cl->next) {
		if (rb->rest == 0) {
			break;
		}

#if defined nginx_version && nginx_version >= 1003009
		tl = ngx_chain_get_free_buf(r->pool, &rb->free);
#else
		tl = ngx_pcalloc(r->pool, sizeof(ngx_chain_t));
#endif
		if (tl == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

#if defined nginx_version && nginx_version < 1003009
		tl->buf = ngx_calloc_buf(r->pool);

		if (tl->buf == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
#endif

		b = tl->buf;

		ngx_memzero(b, sizeof(ngx_buf_t));

		b->temporary = 1;
		b->tag = (ngx_buf_tag_t) &ngx_http_read_client_request_body;
		b->start = cl->buf->start;
		b->pos = cl->buf->pos;
		b->last = cl->buf->last;
		b->end = cl->buf->end;

		size = cl->buf->last - cl->buf->pos;

		if ((off_t) size < rb->rest) {
			cl->buf->pos = cl->buf->last;
			rb->rest -= size;
		} else {
			cl->buf->pos += (size_t) rb->rest;
			rb->rest = 0;
			b->last = cl->buf->pos;
			b->last_buf = 1;
		}

		*ll = tl;
		ll = &tl->next;
	}

	rc = ngx_http_log_collection_process_request_body(r, out);

#if defined nginx_version && nginx_version >= 1003009
	ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
		(ngx_buf_tag_t) &ngx_http_read_client_request_body);
#endif

	return rc;
}

ngx_int_t
ngx_http_log_collection_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_log_collection_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

ngx_int_t
ngx_http_log_collection_get_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
	ngx_http_log_collection_ctx_t	*ctx;
	ngx_str_t						*value;

	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;

	ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);

	if (ctx->redirect_to_backend == 0) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Option redirect_to_backend not set");
		return NGX_ERROR;
	}

	value = (ngx_str_t *) ((char *) ctx->backend_handler_data + data);

	v->data = value->data;
	v->len = value->len;

	return NGX_OK;
}

static char *
ngx_http_log_collection_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_int_t							n;
	ngx_str_t							*value;
	ngx_array_t							**field;
	ngx_http_script_compile_t			sc;
	ngx_http_log_collection_field_template_t	*h;

	field = (ngx_array_t**) (((u_char*)conf) + cmd->offset);

	value = cf->args->elts;

	if (*field == NULL) {
		*field = ngx_array_create(cf->pool, 1, sizeof(ngx_http_log_collection_field_template_t));
		if (*field == NULL) {
			return NGX_CONF_ERROR;
		}
	}

	h = ngx_array_push(*field);
	if (h == NULL) {
		return NGX_CONF_ERROR;
	}

	h->value.hash = 1;
	h->value.key = value[1];
	h->value.value = value[2];
	h->field_lengths = NULL;
	h->field_values = NULL;
	h->value_lengths = NULL;
	h->value_values = NULL;

	/*
	 * Compile field name
	 */
	n = ngx_http_script_variables_count(&value[1]);

	if (n > 0) {
		ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

		sc.cf = cf;
		sc.source = &value[1];
		sc.lengths = &h->field_lengths;
		sc.values = &h->field_values;
		sc.variables = n;
		sc.complete_lengths = 1;
		sc.complete_values = 1;

		if (ngx_http_script_compile(&sc) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	/*
	 * Compile field value
	 */
	n = ngx_http_script_variables_count(&value[2]);

	if (n > 0) {
		ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

		sc.cf = cf;
		sc.source = &value[2];
		sc.lengths = &h->value_lengths;
		sc.values = &h->value_values;
		sc.variables = n;
		sc.complete_lengths = 1;
		sc.complete_values = 1;

		if (ngx_http_script_compile(&sc) != NGX_OK) {
			return NGX_CONF_ERROR;
		}
	}

	return NGX_CONF_OK;
}

/*
 * For backend processing.
 */
static ngx_int_t
ngx_http_log_collection_backend_handler(ngx_http_request_t *r)
{
	ngx_int_t	rc = NGX_OK;
	ngx_str_t	uri, args;
	ngx_uint_t	flags;
	ngx_chain_t	*cl;
	ngx_http_log_collection_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);
	ngx_http_log_collection_loc_conf_t *lclcf = ngx_http_get_module_loc_conf(r, ngx_http_log_collection_module);

	if (lclcf->url_cv) {
		/* complex value */
		if (ngx_http_complex_value(r, lclcf->url_cv, &uri) != NGX_OK) {
			goto failed;
		}

		if (uri.len == 0) {
			ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Empty \"backend_handler\" (was: \"%V\")",
				&lclcf->url_cv->value);
			goto failed;
		}
	} else {
		/* simple value */
		uri = lclcf->url;
	}

	if (lclcf->forward_args) {
		args = r->args; /* forward the query args */
	} else {
		args.len = 0;
		args.data = NULL;
	}

	flags = 0;
	if (ngx_http_parse_unsafe_uri(r, &uri, &args, &flags) != NGX_OK) {
		goto failed;
	}

	r->request_body->bufs = ((ngx_http_log_collection_backend_data_t *) (ctx->backend_handler_data))->chain;

	// Recalculate content length
	r->headers_in.content_length_n = 0;

	for(cl = r->request_body->bufs; cl; cl = cl->next)
		r->headers_in.content_length_n += (cl->buf->last - cl->buf->pos);

	r->headers_in.content_length->value.data = ngx_palloc(r->pool, NGX_OFF_T_LEN);
	if (r->headers_in.content_length->value.data == NULL) {
		goto failed;
	}

	r->headers_in.content_length->value.len =
		ngx_sprintf(r->headers_in.content_length->value.data, "%O", r->headers_in.content_length_n)
		- r->headers_in.content_length->value.data;

#if defined nginx_version && nginx_version >= 8011
	r->main->count--;
#endif

	if(uri.len != 0 && uri.data[0] == '/') {
		rc = ngx_http_internal_redirect(r, &uri, &args);
	} else {
		rc = ngx_http_named_location(r, &uri);
	}

	return rc;

failed:
	rc = NGX_DECLINED;
	return rc;
}

/*
 * Clean up handler in request finalization
 */
static void
ngx_http_log_collection_cleanup_handler(void *data)
{
	ngx_http_log_collection_cleanup_t *cln = data;

	if (!cln->aborted && cln->fd >= 0) {
		if (ngx_close_file(cln->fd) == NGX_FILE_ERROR) {
			ngx_log_error(NGX_LOG_ERR, cln->log, ngx_errno,
				ngx_close_file_n "\"%s\" failed", cln->filename);
		}
	}
}

/*
 * Create the request to the backend.
 */
static void
ngx_http_log_collection_append_str(ngx_http_log_collection_ctx_t *ctx, ngx_buf_t *b,
	ngx_chain_t *cl, ngx_str_t *s, ngx_flag_t end)
{
	ngx_http_log_collection_backend_data_t *bd = ctx->backend_handler_data;

	b->start = b->pos = s->data;
	b->end = b->last = s->data + s->len;
	b->memory = 1;
	b->temporary = 1;
	b->in_file = 0;

	if (end == 0) {
		b->last_buf = 0;
		b->last_in_chain = 0;
	} else {
		b->last_buf = 1;
		b->last_in_chain = 1;
	}

	cl->buf = b;
	cl->next = NULL;

	if(bd->chain == NULL) {
		bd->chain = cl;
		bd->last = cl;
	} else {
		bd->last->next = cl;
		bd->last = cl;
	}
}

static ngx_int_t
ngx_http_log_collection_append_field(ngx_http_log_collection_ctx_t *ctx,
			ngx_str_t *name, ngx_str_t *value, ngx_flag_t end)
{
	ngx_buf_t *b;
	ngx_chain_t *cl;
	size_t offset = 0;
	ngx_uint_t buf_num = 2;
	ngx_uint_t chain_num = 2;
	ngx_http_log_collection_backend_data_t *bd = ctx->backend_handler_data;

	ngx_str_t equal_sign = ngx_string("=");
	ngx_str_t and_sign = ngx_string("&");

	ngx_flag_t start = (bd->chain == NULL) ? 0 : 1;

	if (name->len > 0) {
		if (start) {
			buf_num++;
			chain_num++;
		}

		if (value->len > 0) {
			buf_num++;
			chain_num++;
		}

		if (end == 0) {
			buf_num++;
			chain_num++;
		}

		b = ngx_pcalloc(ctx->request->pool, buf_num * sizeof(ngx_buf_t));
		if (b == NULL) {
			return NGX_LOG_COLLECTION_NOMEM;
		}

		cl = ngx_pcalloc(ctx->request->pool, chain_num * sizeof(ngx_chain_t));

		if (cl == NULL) {
			return NGX_LOG_COLLECTION_NOMEM;
		}

		if (start) {
			ngx_http_log_collection_append_str(ctx, b + offset, cl + offset, &and_sign, end);
			offset++;
		}

		ngx_http_log_collection_append_str(ctx, b + offset, cl + offset, name, end);
		offset++;

		ngx_http_log_collection_append_str(ctx, b + offset, cl + offset, &equal_sign, end);
		offset++;

		if (value->len > 0) {
			ngx_http_log_collection_append_str(ctx, b + offset, cl + offset, value, end);
			offset++;
		}

		if (end == 0) {
			ngx_http_log_collection_append_str(ctx, b + offset, cl + offset, &and_sign, end);
		}
	}

	return NGX_OK;
}

/*
 * Open file for writing
 */
static ngx_int_t
ngx_http_log_collection_open_file(ngx_http_log_collection_ctx_t *ctx)
{
	ngx_err_t err;
	ngx_http_log_collection_loc_conf_t *lclcf;
	ngx_str_t *addr;
	ngx_path_t *path;
	ngx_file_t *file;
	ngx_http_log_collection_cleanup_t  *lccln;
	
	lclcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_log_collection_module);
	addr = &ctx->request->connection->addr_text;
	file = &ctx->output_file;
	path = lclcf->store_path;
	ctx->cln = ngx_pool_cleanup_add(ctx->request->pool, sizeof(ngx_http_log_collection_cleanup_t));

	if (ctx->cln == NULL) {
		return NGX_LOG_COLLECTION_NOMEM;
	}
	
	/* length of uuid: UUID_STRING_LENGTH, format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
	 * max length of ip: IP_STRING_MAX_LENGTH, format: xxx.xxx.xxx.xxx
	 * full format: /path/addr/uuid or /path/addr-uuid
	 */
	file->name.len = path->name.len + 1 + IP_STRING_MAX_LENGTH + 1 + UUID_STRING_LENGTH;
	file->name.data = ngx_pcalloc(ctx->request->pool, file->name.len + 1);

	if (file->name.data == NULL) {
		return NGX_LOG_COLLECTION_NOMEM;
	}

	ngx_memcpy(file->name.data, path->name.data, path->name.len);

	if (lclcf->all_in_single_folder == 0) {
		/* addr/uuid */
		ngx_sprintf(file->name.data + path->name.len, "/%V%Z", addr);
		file->name.data[path->name.len + 1 + addr->len] = '/';

		err = ngx_create_full_path(file->name.data, 0755);

		if (err != 0) {
			ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno, "Failed to create path: %s", file->name.data);
			return NGX_LOG_COLLECTION_IOERROR;
		}

		ngx_sprintf(file->name.data + 1 + path->name.len + 1 + addr->len, "%V%Z", &ctx->client_uuid);
	} else {
		/* addr-uuid */
		ngx_sprintf(file->name.data + path->name.len, "/%V%Z", addr);
		ngx_sprintf(file->name.data + 1 + path->name.len + addr->len, "-%V%Z", &ctx->client_uuid);
	}

	file->fd = ngx_open_file(file->name.data, NGX_FILE_WRONLY, NGX_FILE_CREATE_OR_OPEN, 0600);

	if (file->fd == NGX_INVALID_FILE) {
		err = ngx_errno;

		ngx_log_error(NGX_LOG_ERR, ctx->log, err, "Failed to create file: %s", file->name.data);
		return NGX_LOG_COLLECTION_IOERROR;
	}

	if (ngx_fd_info(file->fd, &file->info) == -1) {
		err = ngx_errno;

		ngx_log_error(NGX_LOG_EMERG, ctx->log, err, ngx_fd_info_n " \"%s\" failed", file->name.data);
	}

	file->offset = (off_t) file->info.st_size;

	ctx->cln->handler = ngx_http_log_collection_cleanup_handler;

	lccln = ctx->cln->data;
	lccln->fd = file->fd;
	lccln->filename = file->name.data;
	lccln->log = ctx->request->connection->log;
	lccln->headers_out = &ctx->request->headers_out;
	lccln->aborted = 0;

	if (ctx->redirect_to_backend) {
		ngx_http_log_collection_backend_data_t *bd = ctx->backend_handler_data;

		ngx_str_t host = ctx->request->headers_in.host->value;
		ngx_flag_t mapped_uri_slash_ended = 1, mapped_uri_slash_started = 1;

		if (lclcf->store_map_to_uri.len > 0) {
			bd->file_loc.len = host.len + ((lclcf->all_in_single_folder == 0) ? addr->len : 0);
			bd->file_loc.len += lclcf->store_map_to_uri.len;

			if (lclcf->store_map_to_uri.data[0] != '/') {
				bd->file_loc.len += 1;
				mapped_uri_slash_started = 0;
			}

			if (lclcf->store_map_to_uri.data[lclcf->store_map_to_uri.len - 1] != '/') {
				bd->file_loc.len += 1; /* will add a '/' */
				mapped_uri_slash_ended = 0;
			}
				
			bd->file_loc.data = ngx_pcalloc(ctx->request->pool, bd->file_loc.len);
			if (bd->file_loc.data == NULL) {
				return NGX_LOG_COLLECTION_NOMEM;
			}

			bd->file_loc.len = 0;
			ngx_memcpy(bd->file_loc.data, host.data, host.len);
			bd->file_loc.len += host.len;

			if (mapped_uri_slash_started == 0) {
				bd->file_loc.data[bd->file_loc.len] = '/';
				bd->file_loc.len++;
			}

			ngx_memcpy(bd->file_loc.data + bd->file_loc.len, lclcf->store_map_to_uri.data,
				lclcf->store_map_to_uri.len);
			bd->file_loc.len += lclcf->store_map_to_uri.len;

			if (mapped_uri_slash_ended == 0) {
				if (lclcf->all_in_single_folder == 0) {
					bd->file_loc.data[bd->file_loc.len] = '/';
					bd->file_loc.len++;
				}
			}

			if (lclcf->all_in_single_folder == 0) {
				ngx_memcpy(bd->file_loc.data + bd->file_loc.len, addr->data, addr->len);
				bd->file_loc.len += addr->len;
			}
		} else {
			bd->file_loc.len = ngx_strlen("Storage directory not mapped.");
			bd->file_loc.data = (u_char *) "Storage directory not mapped.";
		}
	}
	
	return NGX_OK;
}

/*
 * Process file when reaches max file size
 * ngx_http_log_collection_process_max_file
 */
static ngx_int_t
ngx_http_log_collection_process_max_file(ngx_http_log_collection_ctx_t* ctx, ngx_file_t *file,
	u_char *buf, size_t len, ngx_flag_t max)
{
	struct timeval						tp;
	ngx_tm_t							tm;
	ngx_str_t							new_filename;

	if (len > 0) {
	    if (ngx_write_file(&ctx->output_file, buf, len,
			ctx->output_file.offset) == NGX_ERROR)
		{
			ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
				"Write to file \"%V\" failed", &ctx->output_file.name);
			return NGX_LOG_COLLECTION_IOERROR;
		}
	}

	/* Not exceeded the max size */
	if (max == 0) {
		return NGX_OK;
	}

	ngx_close_file(ctx->output_file.fd);

	/* filename-1970_01_01_00_00_00_0000000000 */
	new_filename.len = ctx->output_file.name.len + ngx_strlen(FILE_POSTFIX_FORMAT) +
		2 + sizeof(MAX_NUMBER_STRING) - 1;
	new_filename.data = ngx_pcalloc(ctx->request->pool,
		ctx->output_file.name.len + ngx_strlen(FILE_POSTFIX_FORMAT) + 2 + sizeof(MAX_NUMBER_STRING));

	if (new_filename.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Allocate space for renaming file failed.");
		return NGX_LOG_COLLECTION_NOMEM;
	} else {
		ngx_gettimeofday(&tp);
		ngx_localtime(tp.tv_sec, &tm);

		ngx_sprintf(new_filename.data, "%V%Z", &ctx->output_file.name);
		ngx_sprintf(new_filename.data + ngx_strlen(ctx->output_file.name.data),
			"-%d_%02d_%02d_%02d_%02d_%02d_%L",
			tm.tm_year, tm.tm_mon, tm.tm_mday,
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			tp.tv_usec);

		ngx_rename_file((const char *) ctx->output_file.name.data, (const char *) new_filename.data);

		ctx->output_file.fd = ngx_open_file(ctx->output_file.name.data, NGX_FILE_WRONLY,
			NGX_FILE_CREATE_OR_OPEN, 0600);

		if (ctx->output_file.fd == NGX_INVALID_FILE) {
			ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
				"Fail to open file: %s", ctx->output_file.name.data);
			return NGX_LOG_COLLECTION_IOERROR;
		}

		ctx->output_file.offset = 0;
	}

	return NGX_OK;
}

/*
 * Flush buffer to file
 */
static ngx_int_t
ngx_http_log_collection_flush_to_file(ngx_http_log_collection_ctx_t *ctx)
{
	ngx_http_log_collection_loc_conf_t	*lclcf;
	off_t								len;
	u_char								*buf;
	size_t								delta;
	ngx_int_t							rc = NGX_OK;
	ngx_flag_t							max = 0;

	if (ctx->output_buffer == NULL) {
		return rc;
	}

	lclcf = ngx_http_get_module_loc_conf(ctx->request, ngx_http_log_collection_module);

	buf = ctx->output_buffer;
	len = ctx->output_buffer_len;

	if (lclcf->max_file_size == 0 || len + ctx->output_file.offset <= lclcf->max_file_size) {
		if (ngx_write_file(&ctx->output_file, buf, len,
			ctx->output_file.offset) == NGX_ERROR)
		{
			ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
				"Write to file \"%V\" failed", &ctx->output_file.name);
			rc = NGX_LOG_COLLECTION_IOERROR;
		}
	} else {
		while (len > 0) {
			if (len + ctx->output_file.offset >= lclcf->max_file_size) {
				max = 1;

				/* The size of file to be written is already bigger than the max file size */
				if (ctx->output_file.offset >= lclcf->max_file_size) {
					delta = 0;
				} else {
					delta = lclcf->max_file_size - ctx->output_file.offset;
				}
			} else {
				max = 0;
				delta = len;
			}

			rc = ngx_http_log_collection_process_max_file(ctx, &ctx->output_file, buf, delta, max);
			if (rc != NGX_OK) {
				rc = NGX_LOG_COLLECTION_IOERROR;
				break;
			}

			buf += delta;
			len -= delta;
		}
	}

	return (rc != NGX_OK) ? rc : NGX_OK;
}

static void
ngx_http_log_collection_do_urldecode(u_char *in, size_t *len)
{
	u_char a, b;
	u_char buffer[3];

	if (*len != 3) {
		return;
	}

	a = in[1];
	b = in[2];

	if (a == '%') {
		*len = 2;
		return;
	}

	if (!(a >= 0x30 && a < 0x47)) {
		return;
	}

	if (!(b >= 0x30 && b <0x47)) {
		return;
	}

	buffer[0] = a;
	buffer[1] = b;
	buffer[2] = '\0';

	in[0] = (u_char) strtoul((char *)buffer, NULL, 16);
	*len = 1;
}

static ngx_int_t
ngx_http_log_collection_urldecode(ngx_http_log_collection_decode_output_buffer_data_t *dob,
			u_char *buffer, size_t *len)
{
	/* Note from RFC1630:  "Sequences which start with a percent sign
	 * but are not followed by two hexadecimal characters (0-9, A-F)
	 * are reserved for future extension"
	 */
	size_t		l;
	ngx_uint_t	i = 0;
	u_char		*temp = ngx_pcalloc(dob->pool, *len);

	if (temp == NULL) {
		return NGX_LOG_COLLECTION_NOMEM;
	}

	for (i = 0; i < (ngx_uint_t) *len; /* void */) {
		if (buffer[i] == '%') {
			if ((i == *len - 1) || ((i + 1 == *len - 1) && (buffer[i + 1] == '%'))) {
				dob->need = 2;
				dob->left[0] = buffer[i++];
				*len -= (i == *len) ? 1 : 0;
				break;
			} else if (i + 1 == *len - 1) {
				dob->need = 1;
				dob->left[0] = buffer[i++];
				dob->left[1] = buffer[i++];
				*len -= 2;
				break;
			} else {
				l = 3;
				ngx_http_log_collection_do_urldecode(buffer + i, &l);
				
				if (l == 3) {
					temp[dob->decoded_length++] = buffer[i++];
					temp[dob->decoded_length++] = buffer[i++];
					temp[dob->decoded_length++] = buffer[i++];
				}

				if (l == 2) {
					temp[dob->decoded_length++] = buffer[i++];
				}

				if (l == 1) {
					temp[dob->decoded_length++] = (u_char) buffer[i];
					i += 2;
				}

				i++;
			}
		} else if (buffer[i] == '+') {
			temp[dob->decoded_length++] = ' ';
			i++;
		} else if (buffer[i] == ' ') {
			temp[dob->decoded_length++] = '+';
			i++;
		} else {
			temp[dob->decoded_length++] = buffer[i++];
		}
	}

	if (dob->decoded_length) {
		(void) ngx_memcpy(buffer, temp, dob->decoded_length);
	}

	return NGX_OK;
}

static ngx_int_t
ngx_http_log_collection_construct_backend_request(ngx_http_log_collection_ctx_t *ctx)
{
	size_t		var_len = 0;
	ngx_uint_t	i = 0;
	ngx_str_t	field_name, field_value;
	ngx_chain_t	*cl;
	u_char		*fm, *tl;

	ngx_http_log_collection_backend_data_t *bd = ctx->backend_handler_data;
	ngx_http_log_collection_loc_conf_t *lclcf = ngx_http_get_module_loc_conf(ctx->request,
			ngx_http_log_collection_module);
	ngx_http_log_collection_field_template_t *t = lclcf->field_templates->elts;

	for (cl = bd->field_name_chain; cl; cl = cl->next) {
		var_len += cl->buf->last - cl->buf->pos;
	}

	fm = ngx_pcalloc(ctx->request->pool, var_len);
	if (fm == NULL) {
		ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Alloc space for copying field name failed");
		return NGX_LOG_COLLECTION_NOMEM;
	}

	tl = ngx_pcalloc(ctx->request->pool, ngx_strlen(MAX_NUMBER_STRING));
	if (tl == NULL) {
		ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Alloc space for copying text len failed");
		return NGX_LOG_COLLECTION_NOMEM;
	}

	bd->text_len.data = tl;
	ngx_sprintf(tl, "%O", bd->text_len_n);
	bd->text_len.len = ngx_strlen(tl);

	bd->field_name.data = fm;
	bd->field_name.len = var_len;

	bd->form_name.data = fm;
	bd->form_name.len  = var_len;

	for (cl = bd->field_name_chain; cl; cl = cl->next) {
		(void) ngx_memcpy(fm, cl->buf->pos, cl->buf->last - cl->buf->pos);
	}

	for (i = 0; i < lclcf->field_templates->nelts; i++) {
		if (t[i].field_lengths == NULL) {
			field_name = t[i].value.key;
		} else {
			if (ngx_http_script_run(ctx->request, &field_name, t[i].field_lengths->elts,
				0, t[i].field_values->elts) == NULL) {
				return NGX_LOG_COLLECTION_SCRIPTERROR;
			}
		}

		if (t[i].value_lengths == NULL) {
			field_value = t[i].value.value;
		} else {
			if (ngx_http_script_run(ctx->request, &field_value, t[i].value_lengths->elts,
				0, t[i].value_values->elts) == NULL) {
				return NGX_LOG_COLLECTION_SCRIPTERROR;
			}
		}

		if (ngx_http_log_collection_append_field(ctx, &field_name, &field_value,
			(i != lclcf->field_templates->nelts - 1) ? 0 : 1) != NGX_OK) {
			return NGX_LOG_COLLECTION_SCRIPTERROR;
		}
	}

	ngx_pfree(ctx->request->pool, tl);
	ngx_pfree(ctx->request->pool, fm);

	return NGX_OK;
}

/*
 * process output buffer.
 */
static ngx_int_t
ngx_http_log_collection_process_output_buffer_handler(ngx_http_log_collection_ctx_t *ctx,
		u_char **start, u_char **end)
{
	ngx_int_t rc = NGX_OK;
	u_char *s = *start, *e = *end, *purify_s = NULL, *purify_e = NULL;
	ngx_chain_t	*cl = NULL, *ln = NULL;
	ssize_t		size = 0, val_size = 0;
	const u_char *const_s = *start;
	ngx_http_log_collection_process_request_body_data_t *data = ctx->process_handler_data;
	ngx_http_log_collection_backend_data_t *bd = ctx->backend_handler_data;
	
	data->last_form_name_pos = s;
	data->last_form_value_pos = s;

	while (s <= e) {
		if (data->form_state == log_collection_form_name) {
			if (*s == '&') {
				ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Format is &xx or x&x in the single buffer or xx& in the two buffers");
				return NGX_LOG_COLLECTION_MALFORMED;
			}

			if (s == const_s) {
				if (!data->form_name_flag) {
					if (*s == '=') {
						ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Format is =xx in the single buffer");
						return NGX_LOG_COLLECTION_MALFORMED;
					}

					data->form_name_flag = 1;

					if (ctx->redirect_to_backend) {
						bd->text_len_n = 0;
					}
				}
			}

			/* form name found */
			if (*s == '=' || s == e) {
				size = s - data->last_form_name_pos;

				if (ctx->redirect_to_backend) {
					cl = ngx_pcalloc(ctx->request->pool, sizeof(ngx_chain_t));
					if (cl == NULL) {
						ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
							"Alloc the space for the chain of form name failed");
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}

					cl->buf = ngx_create_temp_buf(ctx->request->pool, size);
					if (cl->buf == NULL) {
						ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
							"Alloc the space for the buf of form name failed");
						return NGX_HTTP_INTERNAL_SERVER_ERROR;
					}

					cl->buf->pos = cl->buf->start;
					cl->buf->last = cl->buf->pos + size;
					cl->buf->last_in_chain = 0;
					cl->buf->last_buf = 0;

					(void) ngx_cpymem(cl->buf->pos, data->last_form_name_pos, size);

					if (*s == '=') {
						cl->buf->last_in_chain = 1;
						cl->buf->last_buf = 1;
					}

					cl->next = NULL;

					if (bd->field_name_chain == NULL) {
						bd->field_name_chain = cl;
						bd->current = bd->field_name_chain;
					} else {
						*bd->next = cl;
						bd->current = *bd->next;
					}

					bd->next = &cl->next;
				}

				if (!data->log_content_purify) {
					/* no need to decode, for it is the form name  */
					if (*s == '=' && s != e) {
						size += 1;
					}

					rc = ngx_http_log_collection_process_buffer_handler(ctx,
						data->last_form_name_pos, size);

					if (rc != NGX_OK) {
						ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Failed to process form name");
						return rc;
					}
				}

				if (*s == '=') {
					data->form_state = log_collection_form_value;

					if (s != e) {
						data->last_form_value_pos = s + 1;
					}
				}
			}
		} else {
			if (*s == '=') {
				ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Format is xx== or xx=yy=");
				return NGX_LOG_COLLECTION_MALFORMED;
			}

			if (*s == '&' || s == e) {
				if (data->log_content_decode) {
					purify_s = data->last_form_value_pos;

					if (data->log_content_purify) {
						purify_e = s;
					} else {
						/* +1: include '&' */
						purify_e = (s == e) ? s : (s + 1);
					}

					rc = data->decode_output_buffer_handler(ctx, &purify_s, &purify_e);

					if (purify_s != data->last_form_value_pos) {
						*start = purify_s;
					}

					if (data->log_content_purify) {
						if (purify_e != s) {
							*end = purify_e;
						}
					} else {
						if ((s == e && purify_e != s) || (s != e && (purify_e != s + 1))) {
							*end = purify_e;
						}
					}

					if (ctx->redirect_to_backend) {
						val_size = purify_e - purify_s;

						if (!data->log_content_purify && *s == '&' && s != e) {
							/* we wrote a '&' */
							val_size -= 1;
						}
					}
				} else {
					size = s - data->last_form_value_pos;
					/* exclude '&' */
					val_size = size;

					if (!data->log_content_purify && *s == '&' && s != e) {
						/* for we will write '&' */
						size += 1;
					}

					rc = ngx_http_log_collection_process_buffer_handler(ctx,
						data->last_form_value_pos, size);

					if (rc != NGX_OK) {
						return rc;
					}
				}

				if (ctx->redirect_to_backend) {
					bd->text_len_n += (off_t) val_size;
				}

				/* form value ended */
				if (*s == '&') {
					data->form_state = log_collection_form_name;
					data->form_name_flag = 0;

					if (s != e) {
						if (ctx->redirect_to_backend) {
							rc = ngx_http_log_collection_construct_backend_request(ctx);

							for (cl = bd->field_name_chain; cl; /* void */) {
								ln = cl;
								cl = cl->next;

								ngx_pfree(ctx->request->pool, ln->buf);
								ngx_free_chain(ctx->request->pool, ln);
							}

							bd->field_name_chain = NULL;
							bd->next = &bd->field_name_chain;
							bd->text_len_n = 0;
						}

						data->last_form_name_pos = s + 1;
					}
				}
			}
		}

		++s;
	}

	if (ctx->written_length + (size_t) (*end - *start) >= ctx->body_length
		&& ctx->redirect_to_backend) {
		bd->current->buf->last_in_chain = 1;
		bd->current->buf->last_buf = 1;

		rc = ngx_http_log_collection_construct_backend_request(ctx);

		for (cl = bd->field_name_chain; cl; /* void */) {
			ln = cl;
			cl = cl->next;

			ngx_pfree(ctx->request->pool, ln->buf);
			ngx_free_chain(ctx->request->pool, ln);
		}

		bd->field_name_chain = NULL;
		bd->next = &bd->field_name_chain;
		bd->text_len_n = 0;
	}

	return rc;
}

/*
 * Callback function for process output_buffer.
 * By default, we call ngx_http_log_collection_process_buffer_handler.
 */
static ngx_int_t
ngx_http_log_collection_decode_output_buffer_handler(ngx_http_log_collection_ctx_t *ctx,
	u_char **start, u_char **end)
{
	ngx_int_t rc;
	size_t l = 3;
	size_t pos = 0;
	size_t len = *end - *start;
	ngx_http_log_collection_decode_output_buffer_data_t *dob;
	ngx_http_log_collection_process_request_body_data_t *prd = ctx->process_handler_data;
	ngx_http_log_collection_backend_data_t *bd = ctx->backend_handler_data;

	if (prd->decode_output_buffer_handler_data == NULL) {
		dob = ngx_pcalloc(ctx->request->pool, 
			sizeof(ngx_http_log_collection_decode_output_buffer_data_t) + 3);

		if (dob == NULL) {
			return NGX_LOG_COLLECTION_NOMEM;
		}

		dob->pool = ctx->request->pool;
		prd->decode_output_buffer_handler_data = (void *) dob;
		dob->buffer_handler = ngx_http_log_collection_process_buffer_handler;
	} else {
		dob = prd->decode_output_buffer_handler_data;
	}

	/* this was a '%' or '%X' in output_buffer last receive */
	if (dob->need) {
		if (ctx->written_length == ctx->body_length - (3 - (size_t) dob->need)) {
			ctx->written_length += 3 - (size_t) dob->need;
			*end = *start;

			if (ctx->redirect_to_backend) {
				bd->text_len_n += 3 - (size_t) dob->need;
			}

			if (dob->buffer_handler) {
				return dob->buffer_handler(ctx, dob->left, 3 - (size_t) dob->need);
			}
		}

		(void) ngx_memcpy(dob->left + 3 - (size_t) dob->need, *start, (size_t) dob->need);
		ngx_http_log_collection_do_urldecode(dob->left, &l);

		if (dob->buffer_handler) {
			(void) dob->buffer_handler(ctx, dob->left, l);
		}

		if (ctx->redirect_to_backend) {
			bd->text_len_n += 3 - (size_t) dob->need;
		}

		ctx->written_length += 3 - (size_t) dob->need;
		pos += (size_t) dob->need;
		len -= (size_t) dob->need;
		dob->need = 0;
	}

	rc = ngx_http_log_collection_urldecode(dob, *start + pos, &len);
	if (rc != NGX_OK) {
		return rc;
	}

	if (dob->buffer_handler) {
		rc = dob->buffer_handler(ctx, *start + pos, dob->decoded_length);
		dob->decoded_length = 0;
	}

	if (dob->need) {
		*end -= 3 - (size_t) dob->need;
	}

	return rc;
}

/*
 * Finish file
 */
static void
ngx_http_log_collection_finish_file(ngx_http_log_collection_ctx_t *ctx)
{
	ngx_http_log_collection_cleanup_t *lccln = ctx->cln->data;

	lccln->fd = -1;

	(void) ngx_http_log_collection_flush_to_file(ctx);
	ngx_close_file(ctx->output_file.fd);
}

/*
 * Seperate writing to file and read body
 * We don't postpone cleanup in request finalization
 */
static void
ngx_http_log_collection_abort_file(ngx_http_log_collection_ctx_t *ctx)
{
	ngx_http_log_collection_cleanup_t *lccln = ctx->cln->data;

	lccln->fd = -1;
	lccln->aborted = 1;
	ngx_close_file(ctx->output_file.fd);
}

/*
 * Some operations when errors occur in reading request body
 */
static void
ngx_http_log_collection_finalization(ngx_http_log_collection_ctx_t *ctx)
{
	if (ctx != NULL) {
		if (ctx->state == log_collection_state_data) {
			(void) ngx_http_log_collection_flush_to_file(ctx);
			ngx_http_log_collection_abort_file(ctx);
		}
	}
}

/*
 * Write client request body to file
 */
ngx_int_t
ngx_http_log_collection_process_buffer_handler(ngx_http_log_collection_ctx_t *ctx, u_char *buffer, size_t len)
{
	ngx_int_t rc;

	ctx->output_buffer = buffer;
	ctx->output_buffer_len = len;

	rc = ngx_http_log_collection_flush_to_file(ctx);
	if (rc != NGX_OK) {
		ngx_http_log_collection_abort_file(ctx);
	}

	return rc;
}

/*
 * Process received data, end points to the address after the last character
 */
static ngx_int_t
ngx_http_log_collection_process_request_body_handler(ngx_http_log_collection_ctx_t *ctx, u_char *start, u_char *end)
{
	ngx_int_t rc;
	ngx_http_log_collection_process_request_body_data_t *data = ctx->process_handler_data;
	ngx_http_log_collection_decode_output_buffer_data_t *dob;

	if (start == end) {
		if (ctx->state != log_collection_state_finish) {
			ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Premature end of body");
			return NGX_LOG_COLLECTION_MALFORMED;
		}

		return NGX_OK;
	}

	if (ctx->written_length != 0) {
		if (ctx->written_length + (size_t) (end - start) > ctx->body_length) {
			rc = data->process_output_buffer_handler(ctx, &start, &end);

			if (rc != NGX_OK) {
				ngx_http_log_collection_abort_file(ctx);
			}

			ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Client request body too large");
			return NGX_LOG_COLLECTION_TOOLARGE;
		}
	}

	for ( ;; ) {
	 	switch(ctx->state) {
			case log_collection_state_header:
				rc = ngx_http_log_collection_open_file(ctx);
				if (rc != NGX_OK) {
					return rc;
				}

				ctx->state = log_collection_state_data;
				break;
			case log_collection_state_data:
				rc = data->process_output_buffer_handler(ctx, &start, &end);

				if (rc != NGX_OK) {
					ngx_http_log_collection_abort_file(ctx);
					return rc;
				}

				ctx->written_length += end - start;
				if (ctx->written_length >= ctx->body_length) {
					ctx->output_buffer = NULL;
					ctx->output_buffer_len = 0;
					ctx->state = log_collection_state_finish;
				} else {
					if (data->log_content_decode) {
						dob = data->decode_output_buffer_handler_data;
						if (ctx->written_length == ctx->body_length - (3 - (size_t) dob->need))
						{
							continue;
						}
					}

					goto done;
				}

				break;
			case log_collection_state_finish:
				ngx_http_log_collection_finish_file(ctx);
				goto done;
		}
	}

done:
	return NGX_OK;
}

/*
 * Process client request body
 * ngx_http_log_collection_process_request_body_handler will be called
 */
ngx_int_t
ngx_http_log_collection_process_request_body(ngx_http_request_t *r, ngx_chain_t *body)
{
	ngx_int_t rc;
	ngx_http_log_collection_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);

	// Feed all the buffers into data handler
	while (body) {
		rc = ctx->process_handler(ctx, body->buf->pos, body->buf->last);

		if(rc != NGX_OK)
			return rc;

		body->buf->pos = body->buf->last;
		body = body->next;
	}

	return NGX_OK;
}

/*
 * Callback function when we finish reading
 * client request body or meet some errors
 */
static void
ngx_http_log_collection_post_handler(ngx_http_request_t *r)
{
	ngx_int_t						rc = NGX_OK;
	ngx_buf_t						*b;
	ngx_chain_t						*out = NULL, **next = NULL;
	ngx_http_log_collection_ctx_t	*ctx;

	ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);

	/* avoid to reach the max keepalive_requests */
	if (r->connection->requests > 0) {
		r->connection->requests--;
	}

	if (r->header_in->pos == r->header_in->last) {
		/* not pipelined request */
		ngx_http_uuid_authen_expire(r, &ctx->client_uuid);
	}

	if (r->discard_body) {
		return;
	} else if (ctx->redirect_to_backend) {
		if (ctx->backend_handler) {
			rc = ctx->backend_handler(r);
			if (rc == NGX_DECLINED) {
				goto local_failed;
			}

			if (rc == NGX_ERROR) {
				goto backend_failed;
			}
		}

		ctx->output_status = rc;
		return;
	} else if (r->headers_in.content_length_n == 0) {
		r->headers_out.status = NGX_HTTP_BAD_REQUEST;
		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		if (b == NULL) {
			goto local_failed;
		}

		b->pos = (u_char *) OUTPUT_STRING_CONTENT_NEEDED;
		b->last = b->pos + ngx_strlen(OUTPUT_STRING_CONTENT_NEEDED);
		b->last_in_chain = 1;
		b->last_buf = 1;
		b->in_file = 0;
	} else {
		r->headers_out.status = NGX_HTTP_OK;
		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		if (b == NULL) {
			goto local_failed;
		}

		b->pos = ngx_pcalloc(r->pool, ngx_strlen(OUTPUT_STRING_DONE CRLF CLIENT_UUID_STRING ": ")
			+ UUID_STRING_LENGTH + ngx_strlen(CRLF OUTPUT_STRING_CONTENT_LENGTH ": ")
			+ ngx_strlen(MAX_NUMBER_STRING));
		if (b->pos == NULL) {
			goto local_failed;
		}

		(void) ngx_memcpy(b->pos, OUTPUT_STRING_DONE CRLF CLIENT_UUID_STRING ": ",
			ngx_strlen(OUTPUT_STRING_DONE CRLF CLIENT_UUID_STRING ": "));
		(void) ngx_memcpy(b->pos + ngx_strlen(b->pos), ctx->client_uuid.data, ctx->client_uuid.len);
		(void) ngx_memcpy(b->pos + ngx_strlen(b->pos), CRLF OUTPUT_STRING_CONTENT_LENGTH ": ",
			ngx_strlen(CRLF OUTPUT_STRING_CONTENT_LENGTH ": "));

		b->last = b->pos + ngx_strlen(OUTPUT_STRING_DONE CRLF CLIENT_UUID_STRING ": ")
			+ UUID_STRING_LENGTH + ngx_strlen(CRLF OUTPUT_STRING_CONTENT_LENGTH ": ");
		b->last_in_chain = 0;
		b->last_buf = 0;
		b->in_file = 0;
	}

	r->headers_out.content_type.len = ngx_strlen("text/plain");
	r->headers_out.content_type.data = (u_char *) "text/plain";

	b->memory = 1;
	r->headers_out.content_length_n = b->last - b->pos;

	out = ngx_pcalloc(ctx->request->pool, ((!r->headers_in.content_length_n) ? 1 : 2) * sizeof(ngx_chain_t));
	if (out == NULL) {
		ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Alloc space for out for response failed");
		goto local_failed;
	}

	out->buf = b;
	out->next = NULL;

	if (r->headers_in.content_length_n > 0) {
		next = &out->next;
		*next = out + 1;

		b = ngx_pcalloc(ctx->request->pool, sizeof(ngx_buf_t));
		if (b == NULL) {
			ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Alloc space for buf for response failed");
			goto local_failed;
		}

		b->last_in_chain = 1;
		b->last_buf = 1;
		b->memory = 1;
		b->in_file = 0;

		b->pos = ngx_pcalloc(r->pool, ngx_strlen(MAX_NUMBER_STRING));
		if (b->pos == NULL) {
			ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
				"Alloc space for the real space of buf for response failed");
			goto local_failed;
		}

		ngx_sprintf(b->pos, "%O", r->headers_in.content_length_n);
		b->last = b->pos + ngx_strlen(b->pos);
		r->headers_out.content_length_n += b->last - b->pos;

		(*next)->buf = b;
		(*next)->next = NULL;
	}

	rc = ngx_http_send_header(r);
	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		ctx->output_status = rc;
		return;
	}

#if defined nginx_version && nginx_version >= 8011
	r->main->count--;
#endif

	ctx->output_status = ngx_http_output_filter(r, out);
	return;

local_failed:
#if defined nginx_version && nginx_version >= 8011
	r->main->count--;
#endif

backend_failed:
	ctx->output_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * The generic action of 'reading client request body', it will
 * be called by ngx_http_read_log_collection_client_request_body
 * and ngx_http_read_log_collection_client_request_body_handler
 */
static ngx_int_t
ngx_http_do_read_log_collection_client_request_body(ngx_http_request_t *r)
{
	ssize_t							size, n, limit;
	ngx_connection_t				*c;
	ngx_http_request_body_t			*rb;
	ngx_int_t						rc;
	ngx_http_core_loc_conf_t		*clcf;
	ngx_msec_t						delay;
	ngx_http_log_collection_ctx_t	*ctx;
	off_t							rest = 0;
	ngx_chain_t						out;

	ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	c = r->connection;
	rb = r->request_body;

	for ( ;; ) {
		for ( ;; ) {
			if (rb->buf->last == rb->buf->end) {
				/* pass buffer to request body filter chain */
				out.buf = rb->buf;
				out.next = NULL;
				*out.buf->last = '\0';

				rc = ngx_http_log_collection_request_body_filter(r, &out);
				if (rc != NGX_OK) {
					goto failed;
				} else {
					break;
				}

#if defined nginx_version && nginx_version >= 1003009
				if (rb->busy != NULL) {
					return NGX_HTTP_INTERNAL_SERVER_ERROR;
				}
#endif

				rb->buf->pos = rb->buf->start;
				rb->buf->last = rb->buf->start;
			}

			size = rb->buf->end - rb->buf->last;
			rest = rb->rest - (rb->buf->last - rb->buf->pos);

			if ((off_t) size > rest) {
				size = (size_t) rest;
			}

			if (ctx->upload_limit_rate) {
				limit = ctx->upload_limit_rate * (ngx_time() - r->start_sec + 1) - ctx->received;

				if (limit < 0) {
					c->read->delayed = 1;
					ngx_add_timer(c->read, (ngx_msec_t) (- limit * 1000 / ctx->upload_limit_rate + 1));

					return NGX_AGAIN;
				}

				if(limit > 0 && size > limit) {
					size = limit;
				}
			}

			n = c->recv(c, rb->buf->last, size);

			ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "Http client request body recv %z", n);

			if (n == NGX_AGAIN) {
				break;
			}

			if (n == 0) {
				ngx_log_error(NGX_LOG_INFO, c->log, 0, "Client closed prematurely connection");
			}

			if (n == 0 || n == NGX_ERROR) {
				c->error = 1;
				return NGX_HTTP_BAD_REQUEST;
			}

			rb->buf->last += n;
			r->request_length += n;
			ctx->received += n;

			if (n == rest) {
				out.buf = rb->buf;
				out.next = NULL;
				*out.buf->last = '\0';

				rc = ngx_http_log_collection_request_body_filter(r, &out);
				if (rc != NGX_OK) {
					goto failed;
				}
			}

			if (rb->rest == 0) {
				break;
			}

			if (rb->buf->last < rb->buf->end) {
				break;
			}

			if (ctx->upload_limit_rate) {
				delay = (ngx_msec_t) (n * 1000 / ctx->upload_limit_rate + 1);

				if (delay > 0) {
					c->read->delayed = 1;
					ngx_add_timer(c->read, delay);
					return NGX_AGAIN;
				}
			}
		}

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0, "http client request body rest %uz", rb->rest);

		if (rb->rest == 0) {
			break;
		}

		if (!c->read->ready) {
			ngx_add_timer(c->read, clcf->client_body_timeout);

			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}

			return NGX_AGAIN;
		}
	}

	if (!r->pipeline) {
		if (c->read->timer_set) {
			ngx_del_timer(c->read);
		}

		/* For we finished reading client request body,
		 * we need not read data any more, so block it.
		 */
		r->read_event_handler = ngx_http_block_reading;
	} else {
		if (!c->read->ready) {
			ngx_add_timer(c->read, clcf->client_body_timeout);

			if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
				return NGX_HTTP_INTERNAL_SERVER_ERROR;
			}
		}
	}

	rb->post_handler(r);

	return r->pipeline ? NGX_AGAIN : ctx->output_status;

failed:
	switch(rc) {
		case NGX_LOG_COLLECTION_MALFORMED:
			return NGX_HTTP_BAD_REQUEST;
		case NGX_LOG_COLLECTION_TOOLARGE:
			return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
		case NGX_LOG_COLLECTION_IOERROR:
			return NGX_HTTP_SERVICE_UNAVAILABLE;
		case NGX_LOG_COLLECTION_BADPROTOCOL:
			return NGX_HTTP_NOT_IMPLEMENTED;
		case NGX_LOG_COLLECTION_NOMEM:
		default:
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}
}

/*
 * Request body may not be read completely once,
 * so ngx_http_read_log_collection_client_request_body_handler is registered
 * and will be called several times
 */
static void
ngx_http_read_log_collection_client_request_body_handler(ngx_http_request_t *r)
{
	ngx_int_t					rc;
	ngx_event_t					*rev = r->connection->read;
	ngx_http_core_loc_conf_t	*clcf;
	ngx_http_log_collection_ctx_t *ctx;
	
	rev = r->connection->read;
	ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);
	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	if (rev->timedout) {
		if(!rev->delayed) {
			r->connection->timedout = 1;
			ngx_http_log_collection_finalization(ctx);
			ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
			return;
		}

		rev->timedout = 0;
		rev->delayed = 0;

		if (!rev->ready) {
			ngx_add_timer(rev, clcf->client_body_timeout);

			if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
				ngx_http_log_collection_finalization(ctx);
				ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}

			return;
		}
	} else {
		if (r->connection->read->delayed) {
			ngx_log_debug0(NGX_LOG_DEBUG_HTTP, rev->log, 0, "Http read delayed");

			if (ngx_handle_read_event(rev, clcf->send_lowat) != NGX_OK) {
				ngx_http_log_collection_finalization(ctx);
				ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
			}

			return;
		}
	}

	rc = ngx_http_do_read_log_collection_client_request_body(r);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		ngx_http_log_collection_finalization(ctx);
		ngx_http_finalize_request(r, rc);
	}
}

/*
 * Read client request body
 * ngx_http_read_log_collection_client_request_body_handler will be called
 */
static ngx_int_t
ngx_http_read_log_collection_client_request_body(ngx_http_request_t *r, ngx_http_client_body_handler_pt post_handler)
{
	ssize_t							size, preread;
	ngx_buf_t						*b;
	ngx_chain_t						out;
	ngx_http_request_body_t			*rb;
	ngx_http_core_loc_conf_t		*clcf;
	ngx_http_log_collection_ctx_t	*ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);
	ngx_int_t						rc;

#if defined nginx_version && nginx_version >= 8011
	r->main->count++;
#endif

	if (
#if defined nginx_version && nginx_version >= 8011
		r != r->main ||
#endif
		r->request_body || r->discard_body) {
		post_handler(r);
		return NGX_OK;
	}

	if (ngx_http_test_expect(r) != NGX_OK) {
		rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		goto done;
	}

	rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
	if (rb == NULL) {
		rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		goto done;
	}

	rb->rest = -1;

	r->request_body = rb;

	if (r->headers_in.content_length_n < 0
#if defined nginx_version && nginx_version >= 1003009
		&& !r->headers_in.chunked
#endif
	) {
		post_handler(r);
		return ctx->output_status;
	}

	rb->post_handler = post_handler;

	/*
	 * set by ngx_pcalloc():
	 *
	 *	rb->bufs = NULL;
	 *	rb->buf = NULL;
	 *	rb->rest = 0;
	 */

	preread = r->header_in->last - r->header_in->pos;

	if (preread) {
		/* there is the pre-read part of the request body */

		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
			"Http client request body preread %uz", preread);

		ctx->received = preread;

		out.buf = r->header_in;
		out.next = NULL;
		*out.buf->last = '\0';

		if (ngx_http_log_collection_request_body_filter(r, &out) != NGX_OK) {
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			goto done;
		}

		r->request_length += preread - (r->header_in->last - r->header_in->pos);

		if (
#if defined nginx_version && nginx_version >= 1003009
			!r->headers_in.chunked &&
#endif
			rb->rest > 0
			&& rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
		{
			/* the whole request body may be placed in r->header_in */
			b = ngx_calloc_buf(r->pool);
			if (b == NULL) {
				rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
				goto done;
			}

			b->temporary = 1;
			b->start = r->header_in->pos;
			b->pos = r->header_in->pos;
			b->last = r->header_in->last;
			b->end = r->header_in->end;

			rb->buf = b;

			r->read_event_handler = ngx_http_read_log_collection_client_request_body_handler;
			r->write_event_handler = ngx_http_request_empty_handler;

			rc = ngx_http_do_read_log_collection_client_request_body(r);
			goto done;
		}
	} else {
		/* set rb->rest */
		if (ngx_http_log_collection_request_body_filter(r, NULL) != NGX_OK) {
			rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
			goto done;
		}
	}

	if (rb->rest == 0) {
		post_handler(r);
		return ctx->output_status;
	}

	if (rb->rest < 0) {
		ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0, "Negative request body rest");
		rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		goto done;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

	size = clcf->client_body_buffer_size;
	size += size >> 2;

	if (
#if defined nginx_version && nginx_version >= 1003009
		!r->headers_in.chunked &&
#endif
		rb->rest < (off_t) size)
	{
		size = (ssize_t) rb->rest;

		if (r->request_body_in_single_buf) {
			size += preread;
		}
	} else {
		size = clcf->client_body_buffer_size;
	}

	rb->buf = ngx_create_temp_buf(r->pool, size);
	if (rb->buf == NULL) {
		rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		goto done;
	}

	r->read_event_handler = ngx_http_read_log_collection_client_request_body_handler;
	r->write_event_handler = ngx_http_request_empty_handler;

	rc = ngx_http_do_read_log_collection_client_request_body(r);

done:
	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
#if defined nginx_version && nginx_version >= 8011
		r->main->count--;
#endif
	}

	return rc;
}

/*
 * ngx_http_log_collection_find_special_header
 * 
 * Find user defined header
 */
static ngx_int_t
ngx_http_log_collection_find_special_header(ngx_http_request_t *r, ngx_str_t *uuid)
{
	return ngx_http_uuid_authen_handler(r, uuid);
}

/*
 * ngx_http_log_collection_parse_request_headers
 *
 * Parse and verify HTTP headers, extract header
 * 
 * Parameters:
 *     ctx        -- log collection context to populate
 *     headers_in -- request headers
 *
 * Return value:
 *     NGX_OK on success
 *     NGX_ERROR if error has occured
 */
static ngx_int_t
ngx_http_log_collection_parse_request_headers(ngx_http_log_collection_ctx_t *ctx,
	ngx_http_headers_in_t *headers_in)
{
	ngx_str_t *content_type;
	ngx_int_t rc, err;
	ngx_http_log_collection_loc_conf_t *lclcf = ngx_http_get_module_loc_conf(ctx->request,
			ngx_http_log_collection_module);

	if (headers_in->content_type == NULL) {
		ngx_log_error(NGX_LOG_ERR, ctx->log, ngx_errno,
			"Missing Content-Type or Content-Length header");

		err = NGX_HTTP_BAD_REQUEST;
		goto failed;
	}

	content_type = &headers_in->content_type->value;
	if (ngx_strncasecmp((u_char *)content_type->data, (u_char *)CONTENT_TYPE_VALUE_STRING,
					sizeof(CONTENT_TYPE_VALUE_STRING) - 1) != 0)
	{
		ngx_log_error(NGX_LOG_ERR, ctx->log, 0,
			"Content-Type is not application/x-www-form-urlencoded: %V", content_type);

		err = NGX_HTTP_UNSUPPORTED_MEDIA_TYPE;
		goto failed;
	}

	rc = ngx_http_log_collection_find_special_header(ctx->request, &ctx->client_uuid);

	if (rc != NGX_DECLINED) {
		if (rc == NGX_HTTP_FORBIDDEN) {
			ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Client-UUID header conflicted");
		} else {
			ngx_log_error(NGX_LOG_ERR, ctx->log, 0, "Client-UUID header missing");
		}

		err = rc;
		goto failed;
	}

	ctx->body_length = (size_t) headers_in->content_length_n;
	if (ctx->body_length > lclcf->max_request_body_size) {
		err = NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
		goto failed;
	}

	return NGX_OK;

failed:
	rc = ngx_http_discard_request_body(ctx->request); /* set discard_body to 1 */
	return (rc != NGX_OK) ? rc : err;
}

void *
ngx_http_log_collection_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_log_collection_loc_conf_t *conf = ngx_pcalloc(cf->pool,
		sizeof(ngx_http_log_collection_loc_conf_t));

	if (conf == NULL) {
		return NULL;
	}

	conf->all_in_single_folder = NGX_CONF_UNSET;
	conf->log_content_decode = NGX_CONF_UNSET;
	conf->log_content_purify = NGX_CONF_UNSET;
	conf->upload_limit_rate = NGX_CONF_UNSET_SIZE;
	conf->max_file_size = NGX_CONF_UNSET;
	conf->max_request_body_size = NGX_CONF_UNSET_SIZE;

	/*
	 * Other members are zeroed by ngx_pcalloc
	 */

	return (void *)conf;
}

char *
ngx_http_log_collection_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_log_collection_loc_conf_t *prev = (ngx_http_log_collection_loc_conf_t *)parent;
	ngx_http_log_collection_loc_conf_t *conf = (ngx_http_log_collection_loc_conf_t *)child;

	ngx_conf_merge_path_value(cf, &conf->store_path, prev->store_path, &ngx_http_log_collection_temp_path);
	ngx_conf_merge_value(conf->all_in_single_folder, prev->all_in_single_folder, 0);
	ngx_conf_merge_value(conf->log_content_decode, prev->log_content_decode, 1);
	ngx_conf_merge_value(conf->log_content_purify, prev->log_content_purify, 1);
	ngx_conf_merge_off_value(conf->max_file_size, prev->max_file_size, 0);
	ngx_conf_merge_size_value(conf->max_request_body_size, prev->max_request_body_size, (size_t) 64 * 1024);
	ngx_conf_merge_size_value(conf->upload_limit_rate, prev->upload_limit_rate, 0);

	return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_log_collection_handler(ngx_http_request_t *r)
{
	ngx_int_t rc;
	ngx_http_log_collection_loc_conf_t *lclcf;
	ngx_http_log_collection_ctx_t *ctx;
	ngx_http_log_collection_process_request_body_data_t *rbd;
	ngx_http_log_collection_backend_data_t *bd;

	// method must be POST
	if (!(r->method & NGX_HTTP_POST)) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	lclcf = ngx_http_get_module_loc_conf(r, ngx_http_log_collection_module);

	if (lclcf->log_collection_switch == 0) {
		return NGX_HTTP_NOT_IMPLEMENTED;
	}

	ctx = ngx_http_get_module_ctx(r, ngx_http_log_collection_module);
	if (ctx == NULL) {
		ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_log_collection_ctx_t));

		if (ctx == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		ngx_http_set_ctx(r, ctx, ngx_http_log_collection_module); /* set r->ctx */
	}

	ctx->state = log_collection_state_header;
	ctx->request = r;
	ctx->log = r->connection->log;
	ctx->process_handler = ngx_http_log_collection_process_request_body_handler;

	if (ctx->process_handler_data == NULL) {
		ctx->process_handler_data = ngx_pcalloc(ctx->request->pool,
			sizeof(ngx_http_log_collection_process_request_body_data_t));

		if (ctx->process_handler_data == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	rbd = ctx->process_handler_data;
	rbd->form_state = log_collection_form_name;
	rbd->process_output_buffer_handler = ngx_http_log_collection_process_output_buffer_handler;

	if (lclcf->log_content_decode == 1) {
		rbd->log_content_decode = 1;
		rbd->decode_output_buffer_handler = ngx_http_log_collection_decode_output_buffer_handler;
	}

	if (lclcf->log_content_purify == 1) {
		rbd->log_content_purify = 1;
	}

	if (lclcf->redirect_to_backend == 1) {
		ctx->redirect_to_backend = 1;
		ctx->backend_handler_data = (void *)&backend_handler_data;
		ctx->backend_handler = ngx_http_log_collection_backend_handler;
		bd = ctx->backend_handler_data;
		bd->next = &bd->field_name_chain;
		bd->chain = bd->last = NULL;
	}

	rc = ngx_http_log_collection_parse_request_headers(ctx, &r->headers_in);

	if (rc != NGX_OK) {
		return rc;
	}

	ctx->written_length    = 0;
	ctx->upload_limit_rate = lclcf->upload_limit_rate;

	rc = ngx_http_read_log_collection_client_request_body(r, ngx_http_log_collection_post_handler);

	if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
		return rc;
	}

	return NGX_DONE;
}

char *
ngx_http_log_collection(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	ngx_str_t					*value;
	ngx_http_core_loc_conf_t	*clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	ngx_http_log_collection_loc_conf_t *lclcf = (ngx_http_log_collection_loc_conf_t *)conf;
	ngx_http_compile_complex_value_t ccv;
	ngx_str_t					switch_on = ngx_string("on");
	ngx_str_t					switch_off = ngx_string("off");

	value = cf->args->elts;

	if (value[1].len == 0) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "empty value in \"%V\" directive", &cmd->name);

		return NGX_CONF_ERROR;
	}

	if (ngx_strncasecmp(value[1].data, switch_on.data, switch_on.len) != 0
		&& ngx_strncasecmp(value[1].data, switch_off.data, switch_off.len) != 0)
	{
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
			"Unrecognized value in \"%V\" directive",
			&value[1]);

		return NGX_CONF_ERROR;
	}

	lclcf->log_collection_switch = ((value[1].len == switch_on.len) &&
		ngx_strncasecmp(value[1].data, switch_on.data, switch_on.len) == 0) ? 1 : 0;

	if (value[2].len != 0 && cf->args->nelts == 3) {
		lclcf->redirect_to_backend = 1;

		if (ngx_http_script_variables_count(&value[2])) {
			/* complex value */
			lclcf->url_cv = ngx_palloc(cf->pool, sizeof(ngx_http_complex_value_t));
			if (lclcf->url_cv == NULL) {
				return NGX_CONF_ERROR;
			}
			
			ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
			
			ccv.cf = cf;
			ccv.value = &value[2];
			ccv.complex_value = lclcf->url_cv;
			
			if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
				return NGX_CONF_ERROR;
			}
		} else {
			/* simple value */
			lclcf->url = value[2];
		}
	}

	clcf->handler = ngx_http_log_collection_handler;

	return NGX_CONF_OK;
}

ngx_int_t
ngx_http_test_expect(ngx_http_request_t *r)
{
	ngx_int_t   n;
	ngx_str_t  *expect;

	if (r->expect_tested
		|| r->headers_in.expect == NULL
		|| r->http_version < NGX_HTTP_VERSION_11)
	{
		return NGX_OK;
	}

	r->expect_tested = 1;

	expect = &r->headers_in.expect->value;

	if (expect->len != sizeof("100-continue") - 1
		|| ngx_strncasecmp(expect->data, (u_char *) "100-continue", sizeof("100-continue") - 1) != 0)
	{
		return NGX_OK;
	}

	ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Send 100 Continue");

	n = r->connection->send(r->connection, (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
		sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

	if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
		return NGX_OK;
	}

	/* we assume that such small packet should be send successfully */

	return NGX_ERROR;
}

