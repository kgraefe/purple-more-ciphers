/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"

#include <pk11pub.h>
#include <prerror.h>

struct NSSDigestContext {
	const char *name;
	SECOidTag algo;

	PK11Context *pk11;
};

static void
nss_digest_init(
	PurpleCipherContext *context, gpointer extra,
	const gchar *name, SECOidTag algo
) {
	struct NSSDigestContext *ctx;

	ctx = g_new0(struct NSSDigestContext, 1);
	ctx->name = name;
	ctx->algo = algo;

	purple_cipher_context_set_data(context, ctx);
	purple_cipher_context_reset(context, extra);
}

static void
nss_digest_reset(PurpleCipherContext *context, gpointer extra) {
	struct NSSDigestContext *ctx = purple_cipher_context_get_data(context);

	if(ctx->pk11) {
		PK11_DestroyContext(ctx->pk11, PR_TRUE);
	}

	ctx->pk11 = PK11_CreateDigestContext(ctx->algo);
	if(PK11_DigestBegin(ctx->pk11) != SECSuccess) {
		error(
			"%s: Could not reset PK11 context: %s\n",
			ctx->name,
			PR_ErrorToString(PR_GetError(), PR_LANGUAGE_EN)
		);
	}
}

static void
nss_digest_uninit(PurpleCipherContext *context) {
	struct NSSDigestContext *ctx = purple_cipher_context_get_data(context);

	if(ctx->pk11) {
		PK11_DestroyContext(ctx->pk11, PR_TRUE);
	}
	memset(ctx, 0, sizeof(struct NSSDigestContext));
	g_free(ctx);
}

static void
nss_digest_append(PurpleCipherContext *context, const guchar *data, size_t len) {
	struct NSSDigestContext *ctx = purple_cipher_context_get_data(context);

	if(PK11_DigestOp(ctx->pk11, data, len) != SECSuccess) {
		error(
			"%s: Could not append data: %s",
			ctx->name,
			PR_ErrorToString(PR_GetError(), PR_LANGUAGE_EN)
		);
	}
}

static gboolean
nss_digest_digest(
	PurpleCipherContext *context, size_t in_len,
	guchar digest[], size_t *out_len
) {
	struct NSSDigestContext *ctx = purple_cipher_context_get_data(context);
	unsigned int ioutlen;

	if(PK11_DigestFinal(ctx->pk11, digest, &ioutlen, in_len) != SECSuccess) {
		error(
			"%s: Could not digest: %s",
			ctx->name,
			PR_ErrorToString(PR_GetError(), PR_LANGUAGE_EN)
		);
		return FALSE;
	}

	*out_len = ioutlen;

	return TRUE;
}

#define GENERATE_CIPHER(name, algo) \
	static void name##_init(PurpleCipherContext *context, gpointer extra) { \
		nss_digest_init(context, extra, #name, algo); \
	} \
	static PurpleCipherOps name##_ops = { \
		NULL,                 /* Set Option       */ \
		NULL,                 /* Get Option       */ \
		name##_init,          /* init             */ \
		nss_digest_reset,     /* reset            */ \
		nss_digest_uninit,    /* uninit           */ \
		NULL,                 /* set iv           */ \
		nss_digest_append,    /* append           */ \
		nss_digest_digest,    /* digest           */ \
		NULL,                 /* encrypt          */ \
		NULL,                 /* decrypt          */ \
		NULL,                 /* set salt         */ \
		NULL,                 /* get salt size    */ \
		NULL,                 /* set key          */ \
		NULL,                 /* get key size     */ \
		NULL,                 /* set batch mode   */ \
		NULL,                 /* get batch mode   */ \
		NULL,                 /* get block size   */ \
		NULL                  /* set key with len */ \
	}
GENERATE_CIPHER(sha384, SEC_OID_SHA384);
GENERATE_CIPHER(sha512, SEC_OID_SHA512);

const struct CipherDesc nss_digest_ciphers[] = {
	{"sha384", &sha384_ops},
	{"sha512", &sha512_ops},
	{NULL}
};
