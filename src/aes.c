/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"

#include <pk11pub.h>
#include <prerror.h>

struct AESGCMContext {
	PK11SymKey *key;
	size_t keylen; /* in bytes */

	guchar *iv;
	size_t ivlen;

	size_t taglen;
};

static void
aes_gcm_init(PurpleCipherContext *context, gpointer extra) {
	struct AESGCMContext *ctx;

	ctx = g_new0(struct AESGCMContext, 1);
	purple_cipher_context_set_data(context, ctx);
	purple_cipher_context_reset(context, extra);
}

static void
aes_gcm_reset(PurpleCipherContext *context, gpointer extra) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);

	if(ctx->key) {
		PK11_FreeSymKey(ctx->key);
	}
	if(ctx->iv) {
		memset(ctx->iv, 0, ctx->ivlen);
		g_free(ctx->iv);
	}

	memset(ctx, 0, sizeof(struct AESGCMContext));
	ctx->keylen = 32; /* default to 256 bits */
	ctx->ivlen = 12;
	ctx->taglen = 16; /* default to 128 bits */
}

static void
aes_gcm_uninit(PurpleCipherContext *context) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);

	purple_cipher_context_reset(context, NULL);

	memset(ctx, 0, sizeof(struct AESGCMContext));
	g_free(ctx);
}

static void
aes_gcm_set_option(PurpleCipherContext *context, const gchar *name, void *value) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);
	int ival = GPOINTER_TO_INT(value);

	if(purple_strequal(name, "taglen")) {
		/* Tag length in Bytes. Defined values are:
		 * - 16 Bytes (128 bits, default)
		 * - 15 Bytes (120 bits)
		 * - 14 Bytes (112 bits)
		 * - 13 Bytes (104 bits)
		 * - 12 Bytes ( 96 bits)
		 * -  8 Bytes ( 64 bits)
		 * -  4 Bytes ( 32 bits)
		 *
		 * However, libnss seems to be okay with other tag lengths too. I
		 * wouldn't recommend them.
		 */
		ctx->taglen = ival;
	}
}

static void *
aes_gcm_get_option(PurpleCipherContext *context, const gchar *name) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);

	if(purple_strequal(name, "taglen")) {
		return GINT_TO_POINTER(ctx->taglen);
	}

	return NULL;
}

static size_t
aes_gcm_get_key_size(PurpleCipherContext *context) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);

	return ctx->keylen;
}

static void
aes_gcm_set_key_with_len(PurpleCipherContext *context, const guchar *key, size_t len) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);
	SECItem key_item;
	PK11SlotInfo *slot;

	if(ctx->key) {
		PK11_FreeSymKey(ctx->key);
		ctx->key = NULL;
	}

	/* We support 128, 192 and 256 bit keys */
	if(len != 16 && len != 24 && len != 32) {
		return;
	}
	ctx->keylen = len;

	key_item.type = siBuffer;
	key_item.data = (guchar *)key;
	key_item.len = len;

	slot = PK11_GetInternalSlot();
	ctx->key = PK11_ImportSymKey(
		slot, CKM_AES_GCM, PK11_OriginUnwrap, CKA_DECRYPT, &key_item, NULL
	);
	PK11_FreeSlot(slot);
}

static void
aes_gcm_set_iv(PurpleCipherContext *context, guchar *iv, size_t len) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);

	if(ctx->iv) {
		memset(ctx->iv, 0, ctx->ivlen);
		g_free(ctx->iv);
	}

	ctx->iv = g_memdup(iv, len);
	ctx->ivlen = len;
}

static int
aes_gcm_encrypt(
	PurpleCipherContext *context, const guchar data[], size_t len,
	guchar output[], size_t *outlen
) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);
	CK_GCM_PARAMS gcm_params;
	SECItem param;

	/* We assume that the output buffer length is input length + tag length. */

	gcm_params.pIv = ctx->iv;
	gcm_params.ulIvLen = ctx->ivlen;
	gcm_params.pAAD = NULL; /* TODO: support optional AAD */
	gcm_params.ulAADLen = 0;
	gcm_params.ulTagBits = ctx->taglen * 8;

	param.type = siBuffer;
	param.data = (unsigned char *) &gcm_params;
	param.len = sizeof(gcm_params);

	if(PK11_Encrypt(
		ctx->key, CKM_AES_GCM, &param,
		output, outlen, len + ctx->taglen,
		data, len
	) != SECSuccess) {
		error(
			"aes-gcm: Could not encrypt: %s\n",
			PR_ErrorToString(PR_GetError(), PR_LANGUAGE_EN)
		);
		return -1;
	}

	return 0;
}

static int
aes_gcm_decrypt(
	PurpleCipherContext *context, const guchar data[], size_t len,
	guchar output[], size_t *outlen
) {
	struct AESGCMContext *ctx = purple_cipher_context_get_data(context);
	CK_GCM_PARAMS gcm_params;
	SECItem param;

	/* Output buffer length must be ciphertext length, hence plaintext length
	 * plus tag length.
	 */

	gcm_params.pIv = ctx->iv;
	gcm_params.ulIvLen = ctx->ivlen;
	gcm_params.pAAD = NULL; /* TODO: support optional AAD */
	gcm_params.ulAADLen = 0;
	gcm_params.ulTagBits = ctx->taglen * 8;

	param.type = siBuffer;
	param.data = (unsigned char *) &gcm_params;
	param.len = sizeof(gcm_params);

	if(PK11_Decrypt(
		ctx->key, CKM_AES_GCM, &param,
		output, outlen, len,
		data, len
	) != SECSuccess) {
		error(
			"aes-gcm: Could not decrypt: %s\n",
			PR_ErrorToString(PR_GetError(), PR_LANGUAGE_EN)
		);
		return -1;
	}

	return 0;
}

static PurpleCipherOps aes_gcm_ops = {
	aes_gcm_set_option,        /* Set Option       */
	aes_gcm_get_option,        /* Get Option       */
	aes_gcm_init,              /* init             */
	aes_gcm_reset,             /* reset            */
	aes_gcm_uninit,            /* uninit           */
	aes_gcm_set_iv,            /* set iv           */
	NULL,                      /* append           */
	NULL,                      /* digest           */
	aes_gcm_encrypt,           /* encrypt          */
	aes_gcm_decrypt,           /* decrypt          */
	NULL,                      /* set salt         */
	NULL,                      /* get salt size    */
	NULL,                      /* set key          */
	aes_gcm_get_key_size,      /* get key size     */
	NULL,                      /* set batch mode   */
	NULL,                      /* get batch mode   */
	NULL,                      /* get block size   */
	aes_gcm_set_key_with_len,  /* set key with len */
};

const struct CipherDesc aes_ciphers[] = {
	{"aes-gcm", &aes_gcm_ops},
	{NULL}
};
