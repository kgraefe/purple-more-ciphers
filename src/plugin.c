/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#include "plugin.h"

#ifdef _WIN32
/* WINDDK_BUILD is defined because the checks around usage of
 * intrisic functions are wrong in nspr */
#define WINDDK_BUILD
#endif

#include <nspr.h>
#include <nss.h>
#include <ssl.h>
#include <sslproto.h>
#include <ocsp.h>

extern const struct CipherDesc argon2_ciphers[];
extern const struct CipherDesc aes_ciphers[];
extern const struct CipherDesc nss_digest_ciphers[];

static void register_ciphers(const struct CipherDesc ciphers[]) {
	const struct CipherDesc *d;

	for(d = ciphers; d->name; d++) {
		if(purple_ciphers_find_cipher(d->name)) {
			warning("Cipher '%s' is already loaded. Skipping.\n", d->name);
			continue;
		}
		purple_ciphers_register_cipher(d->name, d->ops);
	}
}

static void ssl_nss_init_nss(void) {
	static const PRIOMethods *_nss_methods = NULL;
	static PRDescIdentity _identity;

#if NSS_VMAJOR > 3 || ( NSS_VMAJOR == 3 && NSS_VMINOR >= 14 )
	SSLVersionRange supported, enabled;
#endif /* NSS >= 3.14 */

	PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 1);
	NSS_NoDB_Init(".");
#if (NSS_VMAJOR == 3 && (NSS_VMINOR < 15 || (NSS_VMINOR == 15 && NSS_VPATCH < 2)))
	NSS_SetDomesticPolicy();
#endif /* NSS < 3.15.2 */

#if NSS_VMAJOR > 3 || ( NSS_VMAJOR == 3 && NSS_VMINOR >= 14 )
	/* Get the ranges of supported and enabled SSL versions */
	if ((SSL_VersionRangeGetSupported(ssl_variant_stream, &supported) == SECSuccess) &&
			(SSL_VersionRangeGetDefault(ssl_variant_stream, &enabled) == SECSuccess)) {
		purple_debug_info("nss", "TLS supported versions: "
				"0x%04hx through 0x%04hx\n", supported.min, supported.max);
		purple_debug_info("nss", "TLS versions allowed by default: "
				"0x%04hx through 0x%04hx\n", enabled.min, enabled.max);
	}
#endif /* NSS >= 3.14 */

	/** Disable OCSP Checking until we can make that use our HTTP & Proxy stuff */
	CERT_EnableOCSPChecking(PR_FALSE);

	_identity = PR_GetUniqueIdentity("Purple");
	_nss_methods = PR_GetDefaultIOMethods();

}

static gboolean plugin_load(PurplePlugin *plugin) {
	PurplePlugin *nss;

	/* Try to load the ssl-nss plugin shipped with libpurple. If it is not
	 * present we initialize it ourselves.
	 */
	nss = purple_plugins_find_with_name("ssl-nss");
	if(nss) {
		if(!nss->loaded) {
			purple_plugin_load(nss);
		}
	} else {
		ssl_nss_init_nss();
	}

	register_ciphers(argon2_ciphers);
	register_ciphers(aes_ciphers);
	register_ciphers(nss_digest_ciphers);

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

static void init_plugin(PurplePlugin *plugin) {
}
PURPLE_INIT_PLUGIN(PLUGIN_STATIC_NAME, init_plugin, info)
