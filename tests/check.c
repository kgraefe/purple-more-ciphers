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
#include <stdbool.h>

#include "config.h"

#define info(fmt, ...) purple_debug_info("test", fmt, ##__VA_ARGS__)
#define error(fmt, ...) purple_debug_error("test", fmt, ##__VA_ARGS__)

const char *argv0;

#define OPTSTRING "i:s:o:"
#define OPTINDRESET 3
static struct option long_options[] = {
	{"input",    required_argument, 0, 'i'},
	{"salt",     required_argument, 0, 's'},
	{"option",   required_argument, 0, 'o'},
	{0}
};

static void printhelp(void) {
	printf("libpurple more ciphers tests\n");

	printf(
		"\nUsage:\n"
		"    %s [options] hash <algorithm> [-i <input>] [-s <salt>]\n"
		"        Calculate a hash if <input> with and optional <salt> using\n"
		"        <algorithm>. <input> and <salt> must be hexadecimal encoded byte\n"
		"        arrays.\n"
		, argv0
	);

	printf(
		"\nOptions:\n"
		"    -o,--option name=value\n"
		"        Set any integer option supported by the selected cipher. May\n"
		"        be used multiple times.\n"
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

static bool set_cipher_option(PurpleCipherContext *ctx, const char *arg) {
	bool ret = false;
	char *val, *opt = NULL, *t;
	int intVal;

	if(!ctx) {
		goto exit;
	}
	val = strchr(arg, '=');
	if(!val || val == arg) {
		goto exit;
	}

	opt = g_strndup(arg, val - arg);
	val++;

	intVal = strtol(val, &t, 10);
	if(t == val || *t != '\0' || intVal == LONG_MIN || intVal == LONG_MAX) {
		goto exit;
	}

	purple_cipher_context_set_option(ctx, opt, GINT_TO_POINTER(intVal));

	ret = true;

exit:
	g_free(opt);
	return ret;
}

static guchar *unhexlify(gchar *hex, size_t *bufLen) {
	guchar *buf = NULL, *p;
	guchar c;
	size_t len;
	int i;

	len = strlen(hex);
	if(len == 0 || len % 2 != 0) {
		goto error;
	}
	*bufLen = len / 2;
	buf = g_malloc(*bufLen);
	if(!buf) {
		goto error;
	}
	p = buf;

	while(len) {
		for(i = 0, c = 0; i < 2; i++, hex++, len--) {
			c <<= 4;
			switch(*hex) {
			case '0'...'9':
				c |= (*hex - '0');
				break;
			case 'A'...'F':
				c |= 0xA + (*hex - 'A');
				break;
			case 'a'...'f':
				c |= 0xA + (*hex - 'a');
				break;
			default:
				goto error;
			}
		}
		*p = c;
		p++;
	}

	return buf;

error:
	g_free(buf);
	return NULL;
}
static gchar *hexlify(guchar *buf, size_t bufLen) {
	gchar *hex, *p;

	hex = g_malloc(2 * bufLen + 1);
	if(!hex) {
		return NULL;
	}
	p = hex;

	while(bufLen) {
		sprintf(p, "%02x", *buf);
		buf++;
		bufLen--;
		p += 2;
	}

	return hex;
}

int main(int argc, char **argv) {
	int ret = EXIT_FAILURE;
	char c;
	const gchar *action;
	const gchar *algorithm;
	guchar *input = NULL;
	size_t inputLen;
	guchar *salt = NULL;
	size_t saltLen;
	guchar output[4096];
	size_t outputLen;
	gchar *strout = NULL;

	char *pluginpath = NULL;
	char *plugindir = NULL;
	PurplePlugin *plugin;
	PurpleCipher *cipher;
	PurpleCipherContext *ctx = NULL;

	argv0 = argv[0];
	if(argc < 3) {
		printhelp();
		return EXIT_FAILURE;
	}
	action = argv[1];
	algorithm = argv[2];

	optind = OPTINDRESET;
	while((uint8_t)(c = getopt_long(
		argc, argv, OPTSTRING, long_options, NULL
	)) != 0xFF) {
		switch(c) {
		case 'i':
			g_free(input);
			input = unhexlify(optarg, &inputLen);
			if(!input) {
				printhelp();
				goto exit;
			}
			break;

		case 's':
			g_free(salt);
			salt = unhexlify(optarg, &saltLen);
			if(!salt) {
				printhelp();
				goto exit;
			}
			break;

		case 'o':
			/* Will be parsed later */
			break;

		default:
			printhelp();
			goto exit;
		}
	}

	g_log_set_always_fatal(G_LOG_LEVEL_CRITICAL);
	purple_debug_set_enabled(TRUE);

	/* make this a libpurple "ui" */
	purple_eventloop_set_ui_ops(&eventloop_ui_ops);
	purple_util_set_user_dir("/dev/null");
	purple_core_init("check");

	/* Check that cipher is not yet loaded. */
	cipher = purple_ciphers_find_cipher(algorithm);
	if(cipher) {
		error("Cipher %s is already loaded!\n", algorithm);
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
	cipher = purple_ciphers_find_cipher(algorithm);
	if(!cipher) {
		error("Could not load cipher %s!\n", algorithm);
		goto core_quit;
	}
	ctx = purple_cipher_context_new(cipher, NULL);

	/* Set cipher options */
	optind = OPTINDRESET;
	while((uint8_t)(c = getopt_long(
		argc, argv, OPTSTRING, long_options, NULL
	)) != 0xFF) {
		switch(c) {
		case 'o':
			if(!set_cipher_option(ctx, optarg)) {
				printhelp();
				goto core_quit;
			}
			break;
		}
	}

	if(purple_strequal(action, "hash")) {
		if(salt) {
			purple_cipher_context_set_option(ctx,
				"saltlen", GINT_TO_POINTER(saltLen)
			);
			purple_cipher_context_set_salt(ctx, salt);
		}
		if(input) {
			purple_cipher_context_append(ctx, input, inputLen);
		}


		if(!purple_cipher_context_digest(
			ctx, sizeof(output), output, &outputLen
		)) {
			goto core_quit;
		}


		strout = hexlify(output, outputLen);
		info("Digest: %s\n", strout);
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

exit:
	g_free(strout);
	g_free(pluginpath);
	g_free(plugindir);
	g_free(input);
	g_free(salt);

	return ret;
}
