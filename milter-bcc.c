/*
 * milter-bcc.c
 *
 * Copyright 2003, 2006 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-bcc',
 *		`S=unix:/var/lib/milter-bcc/socket, T=S:30s;R:3m'
 *	)dnl
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef SENDMAIL_CF
#define SENDMAIL_CF			"/etc/mail/sendmail.cf"
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <com/snert/lib/version.h>

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netdb.h>

#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/type/Vector.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/getopt.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 75
# error "LibSnert 1.75.8 or better is required"
#endif

# define MILTER_STRING	MILTER_NAME"/"MILTER_VERSION

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define X_SCANNED_BY		"X-Scanned-By"

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

#define FLAG_SKIPALL_CONNECT			0x1
#define FLAG_SKIPALL_MESSAGE			0x2
#define FLAG_SKIPALL_ANY			(FLAG_SKIPALL_CONNECT|FLAG_SKIPALL_MESSAGE)

typedef struct {
	smfWork work;
	int flags;
	Vector addRcpts;			/* per message */
	long addRcptsConnect;			/* per connection */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
} *workspace;

static char internalError[] = "internal error: %s (%d)";

static char empty[] = "";
static const string emptyString = { empty, 0 };
static ParsePath nullPath = {
	0, 0,
	{ empty, 0 },
	{ empty, 0 },
	{ empty, 0 },
	{ empty, 0 },
	{ empty, 0 }
};

static Option optIntro		= { "",			NULL,		"\n# " MILTER_NAME "/" MILTER_VERSION "\n#\n# " MILTER_COPYRIGHT "\n#\n" };

#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders	= { "add-headers",	"-",		"Add extra informational headers when message is copied." };
#endif

static Option *optTable[] = {
	&optIntro,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	NULL
};

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Process the right-hand-side of Milter-Bcc-* lookup.
 */
static sfsistat
addBccRecipient(workspace data, char *rhs, ParsePath *path)
{
	long i;
	sfsistat rc;
	Vector fmtlist;
	char *rcpt, *fmt;

	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "addBccRecipient(%lx, %s, %lx)", TAG_ARGS, (long) data, rhs, (long) path);

	if (data == NULL || path == NULL) {
		rc = smfReply(&data->work, 550, "5.0.0", internalError, strerror(EFAULT), EFAULT);
		goto error0;
	}

	if (rhs == NULL || *rhs == '\0' || (data->flags & FLAG_SKIPALL_ANY) != 0 || strcmp(rhs, "SKIP") == 0) {
		/* No fmt found after pattern match, skip. */
		rc = SMFIS_CONTINUE;
		goto error0;
	}

	if (strcmp(rhs, "SKIPALL") == 0) {
		data->flags |= FLAG_SKIPALL_MESSAGE;
		rc = SMFIS_CONTINUE;
		goto error0;
	}

	if ((fmtlist = TextSplit(rhs, ",", 0)) == NULL) {
		rc = smfReply(&data->work, 452, "4.3.2", internalError, strerror(errno), errno);
		goto error0;
	}

	for (i = 0; i < VectorLength(fmtlist); i++) {
		if ((fmt = VectorGet(fmtlist, i)) == NULL)
			continue;

		if ((rcpt = allocatePath(fmt, path)) == NULL) {
			rc = smfReply(&data->work, 452, "4.3.2", internalError, strerror(errno), errno);
			goto error1;
		}

		if (*rcpt == '\0') {
			free(rcpt);
			continue;
		}

		if (VectorAdd(data->addRcpts, rcpt)) {
			rc = smfReply(&data->work, 452, "4.3.2", internalError, strerror(errno), errno);
			free(rcpt);
			goto error1;
		}

		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "rcpt=%s", TAG_ARGS, rcpt);
	}

	rc = SMFIS_CONTINUE;
error1:
	VectorDestroy(fmtlist);
error0:
	return rc;
}

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	char *value;
	sfsistat rc;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	data->line[0] = '\0';

	if ((data->addRcpts = VectorCreate(10)) == NULL)
		goto error1;

	VectorSetDestroyEntry(data->addRcpts, free);

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, "failed to save workspace");
		goto error2;
	}

	TextCopy(data->client_name, sizeof (data->client_name), client_name);

	value = NULL;
	rc = SMFIS_CONTINUE;

	/*      milter-bcc-connect:a.b.c.d                      RHS
	 *      milter-bcc-connect:a.b.c                        RHS
	 *      milter-bcc-connect:a.b                          RHS
	 *      milter-bcc-connect:a                            RHS
	 *
	 *      milter-bcc-connect:ipv6:a:b:c:d:e:f:g:h         RHS
	 *      milter-bcc-connect:ipv6:a:b:c:d:e:f:g           RHS
	 *      milter-bcc-connect:ipv6:a:b:c:d:e:f             RHS
	 *      milter-bcc-connect:ipv6:a:b:c:d:e               RHS
	 *      milter-bcc-connect:ipv6:a:b:c:d                 RHS
	 *      milter-bcc-connect:ipv6:a:b:c                   RHS
	 *      milter-bcc-connect:ipv6:a:b                     RHS
	 *      milter-bcc-connect:ipv6:a                       RHS
	 *
	 *      milter-bcc-connect:[ip]                         RHS
	 *      milter-bcc-connect:[ipv6:ip]                    RHS
	 *      milter-bcc-connect:some.sub.domain.tld          RHS
	 *      milter-bcc-connect:sub.domain.tld               RHS
	 *      milter-bcc-connect:domain.tld                   RHS
	 *      milter-bcc-connect:tld                          RHS
	 *      milter-bcc-connect:                             RHS
	 */
	if (smfAccessClient(&data->work, MILTER_NAME "-connect:", data->client_name, data->client_addr, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		rc = addBccRecipient(data, value, &nullPath);
		if (data->flags & FLAG_SKIPALL_MESSAGE) {
			/* addBccRecipient not aware of state, so we move the flag. */
			data->flags &= ~FLAG_SKIPALL_MESSAGE;
			data->flags |= FLAG_SKIPALL_CONNECT;
		}
		free(value);
	}

	data->addRcptsConnect = VectorLength(data->addRcpts);

	return rc;
error2:
	VectorDestroy(data->addRcpts);
error1:
	free(data);
error0:
	return SMFIS_ACCEPT;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	sfsistat rc;
	workspace data;
	ParsePath *path;
	const char *error;
	char *value, *auth_authen;

	rc = SMFIS_CONTINUE;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	/* Clear per message flags. */
	data->flags &= ~FLAG_SKIPALL_MESSAGE;

	/* Remove the per message recipients from the list. */
	VectorRemoveSome(data->addRcpts, data->addRcptsConnect, VectorLength(data->addRcpts) - data->addRcptsConnect);

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	if (args[0] == NULL)
		goto error0;

	if ((error = parsePath(args[0], smfFlags, 1, &path)) != NULL) {
		rc = smfReply(&data->work, 553, (const char *) 0, error);
		goto error0;
	}

	/*	milter-bcc-auth:auth_authen			RHS
	 *	milter-bcc-auth:				RHS
	 */
	auth_authen = smfi_getsymval(ctx, smMacro_auth_authen);
	if (smfAccessAuth(&data->work, MILTER_NAME "-auth:", auth_authen, path->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		rc = addBccRecipient(data, value, path);
		free(value);
		if (rc != SMFIS_CONTINUE)
			goto error1;
	}

	/* Skip the null address. */
	if (*path->address.string == '\0')
		goto error1;

	/*	milter-bcc-from:account@some.sub.domain.tld	RHS
	 *	milter-bcc-from:some.sub.domain.tld		RHS
	 *	milter-bcc-from:sub.domain.tld			RHS
	 *	milter-bcc-from:domain.tld			RHS
	 *	milter-bcc-from:tld				RHS
	 *	milter-bcc-from:account@			RHS
	 *	milter-bcc-from:				RHS
	 */
	if (smfAccessEmail(&data->work, MILTER_NAME "-from:", path->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		rc = addBccRecipient(data, value, path);
		free(value);
		if (rc != SMFIS_CONTINUE)
			goto error1;
	}

	/*	milter-bcc-all:account@some.sub.domain.tld	RHS
	 *	milter-bcc-all:some.sub.domain.tld		RHS
	 *	milter-bcc-all:sub.domain.tld			RHS
	 *	milter-bcc-all:domain.tld			RHS
	 *	milter-bcc-all:tld				RHS
	 *	milter-bcc-all:account@				RHS
	 *	milter-bcc-all:					RHS
	 */
	if (smfAccessEmail(&data->work, MILTER_NAME "-all:", path->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		rc = addBccRecipient(data, value, path);
		free(value);
		if (rc != SMFIS_CONTINUE)
			goto error1;
	}
error1:
	free(path);
error0:
	return rc;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	char *value;
	sfsistat rc;
	workspace data;
	ParsePath *path;
	const char *error;

	rc = SMFIS_CONTINUE;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	if (args[0] == NULL)
		goto error0;

	if ((error = parsePath(args[0], smfFlags, 0, &path)) != NULL) {
		rc = smfReply(&data->work, 553, NULL, error);
		goto error0;
	}

	/*	milter-bcc-to:account@some.sub.domain.tld	RHS
	 *	milter-bcc-to:some.sub.domain.tld		RHS
	 *	milter-bcc-to:sub.domain.tld			RHS
	 *	milter-bcc-to:domain.tld			RHS
	 *	milter-bcc-to:tld				RHS
	 *	milter-bcc-to:account@				RHS
	 *	milter-bcc-to:					RHS
	 */
	if (smfAccessEmail(&data->work, MILTER_NAME "-to:", path->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		rc = addBccRecipient(data, value, path);
		free(value);
		if (rc != SMFIS_CONTINUE)
			goto error1;
	}

	/*	milter-bcc-all:account@some.sub.domain.tld	RHS
	 *	milter-bcc-all:some.sub.domain.tld		RHS
	 *	milter-bcc-all:sub.domain.tld			RHS
	 *	milter-bcc-all:domain.tld			RHS
	 *	milter-bcc-all:tld				RHS
	 *	milter-bcc-all:account@				RHS
	 *	milter-bcc-all:					RHS
	 */
	if (smfAccessEmail(&data->work, MILTER_NAME "-all:", path->address.string, NULL, &value) != SMDB_ACCESS_NOT_FOUND) {
		rc = addBccRecipient(data, value, path);
		free(value);
		if (rc != SMFIS_CONTINUE)
			goto error1;
	}
error1:
	free(path);
error0:
	return rc;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	long i;
	char *rcpt;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	for (i = 0; i < VectorLength(data->addRcpts); i++) {
		if ((rcpt = VectorGet(data->addRcpts, i)) != NULL) {
			smfLog(SMF_LOG_INFO, TAG_FORMAT "add RCPT=%s", TAG_ARGS, rcpt);
			(void) smfi_addrcpt(ctx, rcpt);
		}
	}

#ifdef DROPPED_ADD_HEADERS
	/* Add trace to the message. There can be many of these, one
	 * for each filter/host that looks at the message.
	 */
	if (add_headers && 0 < VectorLength(data->addRcpts)) {
		long length;
		const char *if_name, *if_addr;

		if ((if_name = smfi_getsymval(ctx, "{if_name}")) == NULL)
			if_name = smfUndefined;
		if ((if_addr = smfi_getsymval(ctx, "{if_addr}")) == NULL)
			if_addr = "0.0.0.0";

		length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ", if_name, if_addr);
		length += TimeStampAdd(data->line + length, sizeof (data->line) - length);
		(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);
	}
#endif

	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		VectorDestroy(data->addRcpts);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}

/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_VERSION,
	MILTER_COPYRIGHT,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		SMFIF_ADDRCPT,		/* flags */
		filterOpen,		/* connection info filter */
		NULL,			/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		NULL,			/* header filter */
		NULL,			/* end of header */
		NULL,			/* body block filter */
		filterEndMessage,	/* end of message */
		NULL,			/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, NULL			/* SMTP DATA command */
#endif
#if SMFI_VERSION >= 0x01000000
		, NULL			/* xxfi_negotiate */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

static void
atExitCleanUp()
{
	smdbClose(smdbAccess);
	smfAtExitCleanUp();
}

int
main(int argc, char **argv)
{
	int argi;

	/* Define defaults. */
	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	/* Show them the funny farm. */
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(2);
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

#ifdef DROPPED_ADD_HEADERS
	if (optAddHeaders.value)
		milter.handlers.xxfi_flags |= SMFIF_ADDHDRS;
#endif
	openlog(MILTER_NAME, LOG_PID, LOG_MAIL);

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	return smfMainStart(&milter);
}
