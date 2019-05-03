/* Copyright (C) 2019 Konrad Gräfe <konradgraefe@aol.com>
 *
 * This software may be modified and distributed under the terms
 * of the GPLv2 license. See the COPYING file for details.
 */

#ifdef _WIN32
#define _WIN32_IE 0x501
#include <Windows.h>
#endif

#include <purple.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>

#include "config.h"

#define info(fmt, ...) purple_debug_info("test", fmt, ##__VA_ARGS__)
#define error(fmt, ...) purple_debug_error("test", fmt, ##__VA_ARGS__)

const char *argv0;

#define OPTSTRING "hc:a:p:s:"
static struct option long_options[] = {
	{"help",     no_argument,       0, 'h'},
	{"cipher",   required_argument, 0, 'c'},
	{"action",   required_argument, 0, 'a'},
	{"password", required_argument, 0, 'p'},
	{"salt",     required_argument, 0, 's'},
	{0}
};

static void printhelp(void) {
	printf("libpurple more ciphers tests\n");

	printf(
		"\nUsage:\n"
		"    %s -h,--help\n"
		"        Print this help text and exit.\n"
		"    %s [options] -a hash -c cipher -p passwort [-s salt]\n"
		"        Calculate hash of password using cipher and an optional salt.\n"
		, argv0, argv0
	);

	printf(
		"\nOptions:\n"
		"    -d,--debug\n"
		"        Enable debug output\n"
	);
}

static guint
purple_check_input_add(gint fd, PurpleInputCondition condition,
                     PurpleInputFunction function, gpointer data)
{
	/* this is a no-op for now, feel free to implement it */
	return 0;
}
static PurpleEventLoopUiOps eventloop_ui_ops = {
	g_timeout_add,
	g_source_remove,
	purple_check_input_add,
	g_source_remove,
	NULL, /* input_get_error */
#if GLIB_CHECK_VERSION(2,14,0)
	g_timeout_add_seconds,
#else
	NULL,
#endif
	NULL,
	NULL,
	NULL
};

static char *get_plugin_dir(void) {
#ifdef _WIN32
	char *exe = NULL;
	char *exedir = NULL;
	char *plugindir = NULL;
	wchar_t buf[MAXPATHLEN];

	if(GetModuleFileNameW(GetModuleHandle(NULL), buf, MAXPATHLEN) > 0) {
		exe = g_utf16_to_utf8(buf, -1, NULL, NULL, NULL);
	}
	if(!exe) {
		goto exit;
	}

	exedir = g_path_get_dirname(exe);
	if(!exedir) {
		goto exit;
	}

	plugindir = g_build_filename(exedir, "..", "src", NULL);

exit:
	g_free(exe);
	g_free(exedir);
	return plugindir;

#else
	/* TODO */
	return NULL;
#endif
}

int main(int argc, char **argv) {
	char c;
	const char *cipherName = NULL, *action = NULL, *password = NULL;
	char *salt = NULL;
	char *digest = NULL;
	char *plugindir = NULL;
	char *pluginpath = NULL;
	PurplePlugin *plugin;
	PurpleCipher *cipher;
	PurpleCipherContext *ctx = NULL;
	int ret = EXIT_FAILURE;
	size_t buflen;

	argv0 = argv[0];
	while((uint8_t)(c = getopt_long(
		argc, argv, OPTSTRING, long_options, NULL
	)) != 0xFF) {
		switch(c) {
		case 'h':
			printhelp();
			return EXIT_SUCCESS;

		case 'c':
			cipherName = optarg;
			break;

		case 'a':
			action = optarg;
			break;

		case 'p':
			password = optarg;
			break;

		case 's':
			salt = g_strdup(optarg);
			break;

		default:
			printhelp();
			return EXIT_FAILURE;
		}
	}

	if(!cipherName || !action || !password) {
		printhelp();
		return EXIT_FAILURE;
	}

	g_log_set_always_fatal(G_LOG_LEVEL_CRITICAL);
	purple_debug_set_enabled(TRUE);

	/* make this a libpurple "ui" */
	purple_eventloop_set_ui_ops(&eventloop_ui_ops);
	purple_util_set_user_dir("/dev/null");
	purple_core_init("check");

	/* Check that cipher is not yet loaded. */
	cipher = purple_ciphers_find_cipher(cipherName);
	if(cipher) {
		error("Cipher %s is already loaded!\n", cipherName);
		goto core_quit;
	}

	/* Load our own plugin */
	plugindir = get_plugin_dir();
	info("plugindir: %s\n", plugindir);
	if(!plugindir) {
		goto core_quit;
	}
	purple_plugins_add_search_path(plugindir);

	pluginpath = g_build_filename(
		plugindir, "purple-" PLUGIN_STATIC_NAME ".dll", NULL
	);

	purple_plugins_probe("dll");
	plugin = purple_plugins_find_with_filename(pluginpath);
	if(!plugin) {
		error("Could not load %s!\n", pluginpath);
		goto core_quit;
	}
	if(!purple_plugin_load(plugin)) {
		error("Could not load " PLUGIN_ID "!\n");
		goto core_quit;
	}

	/* Load cipher. */
	cipher = purple_ciphers_find_cipher(cipherName);
	if(!cipher) {
		error("Could not load cipher %s!\n", cipherName);
		goto core_quit;
	}

	if(purple_strequal(action, "hash")) {
		ctx = purple_cipher_context_new(cipher, NULL);
		purple_cipher_context_append(ctx, (guchar *)password, strlen(password));

		if(salt) {
			purple_cipher_context_set_option(ctx,
				"saltlen", GINT_TO_POINTER(strlen(salt))
			);
			purple_cipher_context_set_salt(ctx, (guchar *)salt);
		}

		buflen = 2*32 + 1; /* TODO: Query ctx->outlen */
		digest = g_malloc(buflen);
		if(!purple_cipher_context_digest_to_str(ctx, buflen, digest, NULL)) {
			goto core_quit;
		}
		info("Digest: %s\n", digest);
	} else {
		error("Unknown action %s\n", action);
		goto core_quit;
	}

	ret = EXIT_SUCCESS;


core_quit:
	if(ctx) {
		purple_cipher_context_destroy(ctx);
	}
	purple_core_quit();

	g_free(salt);
	g_free(digest);
	g_free(pluginpath);
	g_free(plugindir);

	return ret;
}
