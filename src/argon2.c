/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#ifndef _MSC_VER
#define _MSC_VER 0
#endif
#include <argon2.h>

#include "plugin.h"

static void
argon2_init(PurpleCipherContext *context, gpointer extra) {
	argon2_context *ctx;

	ctx = g_new0(argon2_context, 1);
	purple_cipher_context_set_data(context, ctx);
	purple_cipher_context_reset(context, extra);
}

static void
argon2_reset(PurpleCipherContext *context, gpointer extra) {
	argon2_context *ctx = purple_cipher_context_get_data(context);

	if(ctx->pwd) {
		memset(ctx->pwd, 0, ctx->pwdlen);
		g_free(ctx->pwd);
	}
	if(ctx->salt) {
		memset(ctx->salt, 0, ctx->saltlen);
		g_free(ctx->salt);
	}

	memset(ctx, 0, sizeof(argon2_context));
	ctx->outlen = 32;
	ctx->saltlen = 0;
	ctx->t_cost = 3;    /* 3 passes (time cost) */
	ctx->m_cost = 4096; /* 4 MiB memory cost (in KiB) */
	ctx->lanes = 1;     /* number of lanes (parallelism) */
	ctx->threads = 1;   /* number of threads (parallelism) */
	ctx->version = ARGON2_VERSION_13;
	ctx->flags = ARGON2_DEFAULT_FLAGS;
}

static void
argon2_uninit(PurpleCipherContext *context) {
	argon2_context *ctx = purple_cipher_context_get_data(context);

	purple_cipher_context_reset(context, NULL);

	memset(ctx, 0, sizeof(argon2_context));
	g_free(ctx);
}

static void
argon2_set_option(PurpleCipherContext *context, const gchar *name, void *value) {
	int val = GPOINTER_TO_INT(value);

	argon2_context *ctx = purple_cipher_context_get_data(context);

	if(purple_strequal(name, "outlen")) {
		ctx->outlen = val;
	}
	if(purple_strequal(name, "saltlen")) {
		if(ctx->salt && ctx->saltlen != val) {
			memset(ctx->salt, 0, ctx->saltlen);
			g_free(ctx->salt);
			ctx->salt = NULL;
		}
		ctx->saltlen = val;
	}
	if(purple_strequal(name, "time-cost")) {
		ctx->t_cost = val;
	}
	if(purple_strequal(name, "memory-cost")) { /* in KiB */
		ctx->m_cost = val;
	}
	if(purple_strequal(name, "lanes")) {
		ctx->lanes = val;
	}
	if(purple_strequal(name, "threads")) {
		ctx->threads = val;
	}
}

static void *
argon2_get_option(PurpleCipherContext *context, const gchar *name) {
	argon2_context *ctx = purple_cipher_context_get_data(context);

	if(purple_strequal(name, "outlen")) {
		return GINT_TO_POINTER(ctx->outlen);
	}
	if(purple_strequal(name, "saltlen")) {
		return GINT_TO_POINTER(ctx->saltlen);
	}
	if(purple_strequal(name, "time-cost")) {
		return GINT_TO_POINTER(ctx->t_cost);
	}
	if(purple_strequal(name, "memory-cost")) { /* in KiB */
		return GINT_TO_POINTER(ctx->m_cost);
	}
	if(purple_strequal(name, "lanes")) {
		return GINT_TO_POINTER(ctx->lanes);
	}
	if(purple_strequal(name, "threads")) {
		return GINT_TO_POINTER(ctx->threads);
	}

	return NULL;
}

static void
argon2_set_salt(PurpleCipherContext *context, guchar *salt) {
	argon2_context *ctx = purple_cipher_context_get_data(context);

	/* This is where it gets a bit ugly as libpurple lacks a length parameter
	 * here. We rely on the user to set the saltlen option beforehand.
	 */

	if(ctx->salt) {
		memset(ctx->salt, 0, ctx->saltlen);
		g_free(ctx->salt);
	}
	ctx->salt = g_memdup(salt, ctx->saltlen);
}

static size_t
argon2_get_salt_size(PurpleCipherContext *context) {
	argon2_context *ctx = purple_cipher_context_get_data(context);
	return ctx->saltlen;
}

static void
argon2_append(PurpleCipherContext *context, const guchar *data, size_t len) {
	argon2_context *ctx = purple_cipher_context_get_data(context);

	ctx->pwd = g_realloc(ctx->pwd, ctx->pwdlen + len);
	memcpy(ctx->pwd + ctx->pwdlen, data, len);
	ctx->pwdlen += len;
}

static gboolean
argon2_digest(
	PurpleCipherContext *context, size_t in_len,
	guchar digest[], size_t *out_len,
	argon2_type type
) {
	argon2_context *ctx = purple_cipher_context_get_data(context);
	int ret;

	ctx->out = digest;
	if(in_len < ctx->outlen) {
		error("Could not get argon2 digest: buffer too small!\n");
		return FALSE;
	}

	ret = argon2_ctx(ctx, type);
	if(ret != ARGON2_OK) {
		error("Could not get argon2 digest: %s\n", argon2_error_message(ret));
		return FALSE;
	}

	if(out_len) {
		*out_len = ctx->outlen;
	}

	return TRUE;
}

#define GENERATE_CIPHER(name, type) \
	static gboolean name ## _digest( \
		PurpleCipherContext *context, size_t in_len, \
		guchar digest[], size_t *out_len \
	) { \
		return argon2_digest(context, in_len, digest, out_len, type); \
	} \
	static PurpleCipherOps name ## _ops = { \
		argon2_set_option,    /* Set Option       */ \
		argon2_get_option,    /* Get Option       */ \
		argon2_init,          /* init             */ \
		argon2_reset,         /* reset            */ \
		argon2_uninit,        /* uninit           */ \
		NULL,                 /* set iv           */ \
		argon2_append,        /* append           */ \
		name ## _digest,      /* digest           */ \
		NULL,                 /* encrypt          */ \
		NULL,                 /* decrypt          */ \
		argon2_set_salt,      /* set salt         */ \
		argon2_get_salt_size, /* get salt size    */ \
		NULL,                 /* set key          */ \
		NULL,                 /* get key size     */ \
		NULL,                 /* set batch mode   */ \
		NULL,                 /* get batch mode   */ \
		NULL,                 /* get block size   */ \
		NULL                  /* set key with len */ \
	}
GENERATE_CIPHER(argon2d, Argon2_d);
GENERATE_CIPHER(argon2i, Argon2_i);
GENERATE_CIPHER(argon2id, Argon2_id);

const struct CipherDesc argon2_ciphers[] = {
	{"argon2d", &argon2d_ops},
	{"argon2i", &argon2i_ops},
	{"argon2id", &argon2id_ops},
	{NULL}
};
