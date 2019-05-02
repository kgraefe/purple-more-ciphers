/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"

extern const struct CipherDesc argon2_ciphers[];

static GList *loaded = NULL;

static GList *
register_cipher(GList *loaded, const char *name, PurpleCipherOps *ops) {
	PurpleCipher *c;

	c = purple_ciphers_register_cipher(name, ops);
	if(c) {
		loaded = g_list_append(loaded, c);
	}
	return loaded;
}

static gboolean plugin_load(PurplePlugin *plugin) {
	const struct CipherDesc *d;

	for(d = argon2_ciphers; d->name; d++) {
		loaded = register_cipher(loaded, d->name, d->ops);
	}

	debug("Additional ciphers loaded.\n");
	return TRUE;
}

static gboolean plugin_unload(PurplePlugin *plugin) {
	GList *l, *ll;
	PurpleCipher *c;

	for(l = loaded; l; l = ll) {
		ll = l->next;

		c = PURPLE_CIPHER(l->data);
		loaded = g_list_remove(loaded, c);
		purple_ciphers_unregister_cipher(c);
	}
	g_list_free(loaded);
	loaded = NULL;

	debug("Additional ciphers unloaded.\n");
	return TRUE;
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
	"Additional ciphers",         /* name           */
	PLUGIN_VERSION,               /* version        */
	"Additional ciphers",         /* summary        */
	"Additional ciphers",         /* description    */
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
