/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"

#include <pk11pub.h>
#include <prerror.h>

static gboolean
random_digest(
	PurpleCipherContext *context, size_t in_len,
	guchar digest[], size_t *out_len
) {
	PK11SlotInfo *slot = NULL;
	gboolean ret = FALSE;

	slot = PK11_GetInternalSlot();
	if(!slot) {
		error("random: Could not get PK11 slot!\n");
		goto error;
	}

	if(PK11_GenerateRandomOnSlot(slot, digest, in_len) != SECSuccess) {
		error("random: Could not generate random bytes\n");
		goto error;
	}

	*out_len = in_len;
	ret = TRUE;

error:
	if(slot) {
		PK11_FreeSlot(slot);
	}
	return ret;
}

static PurpleCipherOps random_ops = {
	NULL,                 /* Set Option       */
	NULL,                 /* Get Option       */
	NULL,                 /* init             */
	NULL,                 /* reset            */
	NULL,                 /* uninit           */
	NULL,                 /* set iv           */
	NULL,                 /* append           */
	random_digest,        /* digest           */
	NULL,                 /* encrypt          */
	NULL,                 /* decrypt          */
	NULL,                 /* set salt         */
	NULL,                 /* get salt size    */
	NULL,                 /* set key          */
	NULL,                 /* get key size     */
	NULL,                 /* set batch mode   */
	NULL,                 /* get batch mode   */
	NULL,                 /* get block size   */
	NULL                  /* set key with len */
};

const struct CipherDesc random_ciphers[] = {
	{"random", &random_ops},
	{NULL}
};

