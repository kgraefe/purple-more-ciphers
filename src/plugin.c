/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"

extern const struct CipherDesc argon2_ciphers[];
extern const struct CipherDesc aes_ciphers[];

static gboolean plugin_load(PurplePlugin *plugin) {
	const struct CipherDesc *d;

	for(d = argon2_ciphers; d->name; d++) {
		purple_ciphers_register_cipher(d->name, d->ops);
	}
	for(d = aes_ciphers; d->name; d++) {
		purple_ciphers_register_cipher(d->name, d->ops);
	}

	return TRUE;
}

static gboolean plugin_unload(PurplePlugin *plugin) {
	return FALSE;
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,       /* type           */
	NULL,                         /* ui_requirement */
	PURPLE_PLUGIN_FLAG_INVISIBLE, /* flags          */
	NULL,                         /* dependencies   */
	PURPLE_PRIORITY_DEFAULT,      /* priority       */

	PLUGIN_ID,                    /* id             */
	"More ciphers for libpurple", /* name           */
	PLUGIN_VERSION,               /* version        */
	"More ciphers for libpurple", /* summary        */
	"More ciphers for libpurple", /* description    */
	PLUGIN_AUTHOR,                /* author         */
	PLUGIN_WEBSITE,               /* homepage       */

	plugin_load,                  /* load           */
	plugin_unload,                /* unload         */
	NULL,                         /* destroy        */

	NULL,                         /* ui_info        */
	NULL,                         /* extra_info     */
	NULL,                         /* prefs_info     */
	NULL,                         /* actions        */
	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static void init_plugin(PurplePlugin *plugin) {}
PURPLE_INIT_PLUGIN(PLUGIN_STATIC_NAME, init_plugin, info)
