/*
///////////////////////////////////////////////////////
kavsshwsproxy - SSH via WebSocket proxy

Author: kuzinandrey@yandex.ru
URL: https://www.github.com/KuzinAndrey/kavsshwsproxy
License: MIT
///////////////////////////////////////////////////////
Dependency:
    libssh2 - library for SSH communication
    libevent - Event notification library (with WebSocket support !!!)
    zlib - general compession library 1.2.11

History:
    2024-05-04 - Initial version
    2024-05-05 - Add session gzipped log write, SSL connection support
    2024-05-06 - Add cli options, help page, terminal size in URL
    2024-05-08 - Connection list, web /status page, MT refactor
    2024-05-12 - Fix recording, add pty size
///////////////////////////////////////////////////////
*/

#define PROJECT_NAME "kavsshwsproxy"
#define PROJECT_VERSION "0.3"
#define PROJECT_DATE "2024-05-12"
#define PROJECT_GIT "https://github.com/KuzinAndrey"
#define REC_HEADER_SIGN "SSH_SESSION_RECORD"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/ws.h>
#include <evhttp.h>
#include <event2/bufferevent_ssl.h>
#include <event2/thread.h>

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <syslog.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include <pthread.h>

#include <libssh2.h>
#include <zlib.h>

#define OPENSSL_NO_DEPRECATED_3_0
#include <openssl/ssl.h>
#include <openssl/err.h>

#ifndef LIBSSH2_HOSTKEY_HASH_SHA1_LEN
#define LIBSSH2_HOSTKEY_HASH_SHA1_LEN 20
#endif

// #define DEBUG(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr,"\n"); }
#define DEBUG(...) syslog(LOG_INFO | LOG_PID, __VA_ARGS__);

#define DIE_OPENSSL(name) { fprintf(stderr, \
	"ERROR: openssl function %s (%s:%d)\n", \
	name, __FILE__, __LINE__); \
	ERR_print_errors_fp(stderr); \
	exit(EXIT_FAILURE); }

#define DIR_UUID_FORMAT "%s/%08lx-%04lx-%04lx-%04lx-%012lx.%s"

// Libevent global objects
struct event_base *base;
struct event *sig_int;
struct event *sig_term;
struct evhttp *http_server;

// Options from cli
char *opt_server_bind = "0.0.0.0";
int opt_server_port = 6970;
int opt_use_ssl = 1;
int opt_foreground = 0;
char *opt_ssh_term = NULL; // "xterm-color";
char *opt_cert_full_chain = "fullchain.pem";
char *opt_cert_primary = "prikey.pem";
char *opt_tmp_dir = "/tmp";
char *opt_records_dir = "/tmp/records";

struct proxy_session {
	pthread_t th;
	pthread_mutex_t mutex;
	struct proxy_session *next;
	struct proxy_session *prev;

	struct timeval start_time;
	size_t ssh_to_ws;
	size_t ws_to_ssh;

	libssh2_socket_t sock;
	struct sockaddr_in sin;
	char *user;
	char *pubkey;
	char *prikey;
	char *keypass;
	char *server_ip;
	in_port_t port;
	int pty_cols;
	int pty_rows;
	LIBSSH2_SESSION *session;
	LIBSSH2_LISTENER *listener;
	LIBSSH2_CHANNEL *channel;
	int ssh_state; // 0 - unknown, 1 - work, 2 - closed

	struct evws_connection *evws;
	char name[INET6_ADDRSTRLEN];
	int websocket_state; // 0 - unknown, 1 - work, 2- closed

	unsigned long uuid[5];
	int record;
	char *record_name;
	gzFile record_fd;
};

static pthread_mutex_t proxy_session_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct proxy_session *proxy_session_list = NULL;
int terminate = 0;

// Call back for incoming websocket data write to ssh channel
static void
websocket_msg_cb(struct evws_connection *evws, int type, const unsigned char *data,
	size_t len, void *arg)
{
	struct proxy_session *self = arg;
	struct timeval curtime = {0};

	if (self->ssh_state == 2) {
		DEBUG("SSH is closed, close websocket %s too", self->name);
		evws_close(self->evws, WS_CR_NORMAL);
		return;
	}

	ssize_t n;
	size_t pos = 0;
	do {
		if (self->ssh_state == 1) {
			pthread_mutex_lock(&self->mutex);
			if (!self->channel) {
				pthread_mutex_unlock(&self->mutex);
				break;
			}
			n = libssh2_channel_write(self->channel,(const char *) data + pos, len - pos);
			pthread_mutex_unlock(&self->mutex);
			if (n == LIBSSH2_ERROR_EAGAIN) continue;
			else if (n < 0) break;
			pos += n;
			self->ws_to_ssh += n;
		} else break;

		if (self->record && n > 0) {
			gettimeofday(&curtime, NULL);
			pthread_mutex_lock(&self->mutex);
			if (self->record_fd) {
				gzwrite(self->record_fd, &curtime, sizeof(struct timeval));
				gzwrite(self->record_fd,">>",3);
				gzwrite(self->record_fd, &n, sizeof(n));
				gzwrite(self->record_fd, data + pos, n);
			}
			pthread_mutex_unlock(&self->mutex);
		}
	} while (len - pos > 0);
} // websocket_msg_cb()

static void
websocket_close_cb(struct evws_connection *evws, void *arg)
{
	struct proxy_session *self = arg;
	DEBUG("WebSocket '%s' disconnected", self->name);
	self->websocket_state = 2;
} // websocket_close_cb()

static const char *
nice_addr(const char *addr)
{
	if (strncmp(addr, "::ffff:", 7) == 0)
		addr += 7;

	return addr;
}

static void
addr2str(struct sockaddr *sa, char *addr, size_t len)
{
	const char *nice;
	unsigned short port;
	size_t adlen;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)sa;
		port = ntohs(s->sin_port);
		evutil_inet_ntop(AF_INET, &s->sin_addr, addr, len);
	} else { // AF_INET6
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)sa;
		port = ntohs(s->sin6_port);
		evutil_inet_ntop(AF_INET6, &s->sin6_addr, addr, len);
		nice = nice_addr(addr);
		if (nice != addr) {
			size_t len = strlen(addr) - (nice - addr);
			memmove(addr, nice, len);
			addr[len] = 0;
		}
	}
	adlen = strlen(addr);
	snprintf(addr + adlen, len - adlen, ":%d", port);
}


// callback for creating new SSL connection wrapped in OpenSSL bufferevent
static struct bufferevent *bevcb(struct event_base *base, void *arg) {
	struct bufferevent *r;
	SSL_CTX *ctx = (SSL_CTX *)arg;
	r = bufferevent_openssl_socket_new(base, -1, SSL_new(ctx),
		BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	return r;
} // bevcb()


static int ssh_waitsocket(libssh2_socket_t socket_fd, LIBSSH2_SESSION *session)
{
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 100000 };
	fd_set fd;
	fd_set *writefd = NULL;
	fd_set *readfd = NULL;
	int dir;

	FD_ZERO(&fd);
	FD_SET(socket_fd, &fd);
	dir = libssh2_session_block_directions(session);
	if(dir & LIBSSH2_SESSION_BLOCK_INBOUND) readfd = &fd;
	if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) writefd = &fd;
	return select((int)(socket_fd + 1), readfd, writefd, NULL, &timeout);
} // ssh_waitsocket()


void clean_proxy_session(struct proxy_session *sess) {
	if (!sess) return;

	if (sess->session) {
		libssh2_session_disconnect(sess->session, "Normal Shutdown");
		libssh2_session_free(sess->session);
		sess->session = NULL;
	}

	if (sess->sock != LIBSSH2_INVALID_SOCKET) {
		DEBUG("Close ssh socket #%d with %s:%d", sess->sock, sess->server_ip, sess->port);
		shutdown(sess->sock, SHUT_RDWR);
		close(sess->sock);
		sess->sock = LIBSSH2_INVALID_SOCKET;
	}

	if (sess->user) { free(sess->user); sess->user = NULL; }
	if (sess->pubkey) { free(sess->pubkey); sess->pubkey = NULL; }
	if (sess->prikey) { free(sess->prikey); sess->prikey = NULL; }
	if (sess->keypass) { free(sess->keypass); sess->keypass = NULL; }
	if (sess->server_ip) { free(sess->server_ip); sess->server_ip = NULL; }

	sess->ssh_state = 2; // closed
} // clean_proxy_session()


int up_ssh_session(struct proxy_session *sess) {
	int rc = 0;
	char *err = NULL;

	if (!sess->user || !sess->keypass || !sess->server_ip) {
		DEBUG("No some SSH session parameters");
		goto return_error;
	}

	sess->sin.sin_family = AF_INET;
	sess->sin.sin_addr.s_addr = inet_addr(sess->server_ip);
	if (INADDR_NONE == sess->sin.sin_addr.s_addr) {
		DEBUG("Can't parse server ip \"%s\" for ssh session", sess->server_ip);
		goto return_error;
	}

	sess->sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sess->sock == LIBSSH2_INVALID_SOCKET) {
		DEBUG("Can't create socket for ssh session");
		goto return_error;
	}

	sess->sin.sin_port = htons(sess->port);
	if (connect(sess->sock, (struct sockaddr*)(&sess->sin), sizeof(struct sockaddr_in))) {
		DEBUG("Can't make tcp connection to %s:%d - %s",
			inet_ntoa(sess->sin.sin_addr), ntohs(sess->sin.sin_port),
			strerror(errno));
		goto return_error;
	}

	DEBUG("Try make SSH connection to %s:%d",
		inet_ntoa(sess->sin.sin_addr), ntohs(sess->sin.sin_port));

	sess->session = libssh2_session_init();
	if (!sess->session) {
		DEBUG("Can't init SSH session");
		goto return_error;
	}

	libssh2_session_set_blocking(sess->session, 0); // non-blocking mode
	libssh2_keepalive_config(sess->session, 1, 30);

	while ((rc = libssh2_session_handshake(sess->session, sess->sock)) ==
		LIBSSH2_ERROR_EAGAIN);
	if (rc) {
		DEBUG("Can't make ssh handshake - %d", rc);
		goto return_error;
	}

	const char *fingerprint = libssh2_hostkey_hash(sess->session,
		LIBSSH2_HOSTKEY_HASH_SHA1);
	if (!fingerprint) {
		DEBUG("Can't get SSH server SHA1 fingerprint");
		goto return_error;
	}

	// // TODO write to buffer
	// DEBUG("SSH server fingerprint: ");
	// for (int i = 0; i < LIBSSH2_HOSTKEY_HASH_SHA1_LEN; i++)
	// 	DEBUG("%02X", (unsigned char)fingerprint[i]);
	// DEBUG("\n");

	char *userauthlist = NULL;
	do {
		userauthlist = libssh2_userauth_list(sess->session, sess->user, strlen(sess->user));
		if (userauthlist ||
			LIBSSH2_ERROR_EAGAIN != libssh2_session_last_error(
				sess->session, NULL, NULL, 0)) break;

		ssh_waitsocket(sess->sock, sess->session);
	} while(1);
	if (!userauthlist) {
		DEBUG("Can't get SSH auth methods list for user \"%s\"", sess->user);
		goto return_error;
	}

	DEBUG("SSH auth methods list: %s", userauthlist);

	if (strstr(userauthlist, "publickey") && sess->pubkey && sess->prikey) {
		DEBUG("Auth as \"%s\" by public key: %s", sess->user, sess->pubkey);

		while ((rc = libssh2_userauth_publickey_fromfile(sess->session,
			sess->user, sess->pubkey, sess->prikey, sess->keypass))
			== LIBSSH2_ERROR_EAGAIN) {};

		if (-1 == remove(sess->pubkey)) {
			DEBUG("Can't remove file %s - %s", sess->pubkey, strerror(errno));
		};

		if (-1 == remove(sess->prikey)) {
			DEBUG("Can't remove file %s - %s", sess->prikey, strerror(errno));
		};

		if (sess->keypass) {
			char *p = sess->keypass;
			while (*p != 0) { *p = '*'; p++; }
			free(sess->keypass);
			sess->keypass = NULL;
		}

		if (rc) {
			DEBUG("Auth by public key failed [%s, %s]", sess->server_ip, sess->user);
			goto return_error;
		}
	} else {
		DEBUG("Can't find any valid auth methods [%s]", sess->server_ip);
		goto return_error;
	}

	DEBUG("Auth successful [%s@%s:%d]", sess->user, sess->server_ip, sess->port);
	return 0;

return_error:
	rc = libssh2_session_last_error(sess->session, &err, NULL, 0);
	DEBUG("libssh2 error: %d - %s", rc, err);
	clean_proxy_session(sess);
	return 1;
} // up_ssh_session()


void clean_ssh_channel(struct proxy_session *sess) {
	if (!sess || !sess->session || !sess->channel) return;
	int rc;

	while (( rc = libssh2_channel_close(sess->channel)) == LIBSSH2_ERROR_EAGAIN) {
		ssh_waitsocket(sess->sock, sess->session);
	}

	libssh2_channel_free(sess->channel);
	sess->channel = NULL;
} // clean_ssh_channel()


void *ssh_session_read_thread(void *data) {
	struct proxy_session *self = data;
	char buf[1024 * 32];
	size_t s;
	struct timeval curtime = {0};

	if (self->record) {
		pthread_mutex_lock(&self->mutex);
		sprintf(buf, DIR_UUID_FORMAT, opt_tmp_dir,
			self->uuid[0], self->uuid[1], self->uuid[2],
			self->uuid[3], self->uuid[4],"sshtmp");
		self->record_fd = gzopen(buf,"w");
		if (self->record_fd) {
			self->record_name = strdup(buf);
			gettimeofday(&self->start_time, NULL);
			gzwrite(self->record_fd, REC_HEADER_SIGN, strlen(REC_HEADER_SIGN) + 1);
			gzwrite(self->record_fd, PROJECT_NAME, sizeof(PROJECT_NAME));
			gzwrite(self->record_fd, PROJECT_VERSION, sizeof(PROJECT_VERSION));
			gzwrite(self->record_fd, self->server_ip, strlen(self->server_ip) + 1);
			gzwrite(self->record_fd, &self->port, sizeof(self->port));
			gzwrite(self->record_fd, self->name, strlen(self->name) + 1);
			gzwrite(self->record_fd, self->user, strlen(self->user) + 1);
			gzwrite(self->record_fd, self->uuid, sizeof(self->uuid));
			gzwrite(self->record_fd, &self->pty_cols, sizeof(self->pty_cols));
			gzwrite(self->record_fd, &self->pty_rows, sizeof(self->pty_rows));
			s = sizeof(struct timeval);
			gzwrite(self->record_fd, &s, sizeof(s));
			gzwrite(self->record_fd, &self->start_time, sizeof(struct timeval));
		}
		pthread_mutex_unlock(&self->mutex);
	}

	while (0 == self->websocket_state) {};

	while (!libssh2_channel_eof(self->channel)
		&& 1 == self->websocket_state
		&& 0 == terminate
	) {
		ssize_t len = libssh2_channel_read(self->channel, buf, sizeof(buf));
		if(len < 0) {
			if (LIBSSH2_ERROR_EAGAIN == len) {
				ssh_waitsocket(self->sock, self->session);
				continue;
			}
			DEBUG( "Unable to read response from %s:%d - %ld", self->server_ip, self->port, (long)len);
			break;
		} else {
			if (self->websocket_state == 1 && self->evws) {
				evws_send_binary(self->evws, buf, len);
				self->ssh_to_ws += len;
				if (self->record) {
					pthread_mutex_lock(&self->mutex);
					if (self->record_fd) {
						gettimeofday(&curtime, NULL);
						gzwrite(self->record_fd, &curtime, sizeof(struct timeval));
						gzwrite(self->record_fd,"<<",3);
						gzwrite(self->record_fd, &len, sizeof(len));
						gzwrite(self->record_fd, buf, len);
					}
					pthread_mutex_unlock(&self->mutex);
				}
			} else break;
		}
	} // while
	self->ssh_state = 0; // unknown

	pthread_mutex_lock(&self->mutex);

	clean_ssh_channel(self);
	clean_proxy_session(self);
	if (self->record_fd) {
		gzclose(self->record_fd);
		self->record_fd = NULL;
		if (self->record_name) {
			sprintf(buf, DIR_UUID_FORMAT, opt_records_dir,
				self->uuid[0], self->uuid[1], self->uuid[2],
				self->uuid[3], self->uuid[4],"sshproxyrec.gz");
			if (-1 == rename(self->record_name, buf)) {
				DEBUG("Can't rename %s to %s", self->record_name, buf);
			} else {
				DEBUG("Rename %s to %s", self->record_name, buf);
			}
		}
	}
	if (self->record_name) {
		free(self->record_name);
		self->record_name = NULL;
	}

	pthread_mutex_unlock(&self->mutex);

	sleep(1);
	if (self->websocket_state == 1) {
		DEBUG("WebSocket '%s' is work, close it too", self->name);
		evws_close(self->evws, WS_CR_NORMAL);
	}

	memset(&self->th, 0, sizeof(self->th));
	pthread_exit(NULL);
} // ssh_session_read_thread()


int up_ssh_channel(struct proxy_session *sess) {
	int rc;
	char *err = NULL;
	if (!sess) return 1;
	if (!sess->session) return 1;

	do {
		sess->channel = libssh2_channel_open_session(sess->session);
		if (sess->channel ||
			LIBSSH2_ERROR_EAGAIN != libssh2_session_last_error(
				sess->session, NULL, NULL, 0)) break;

		ssh_waitsocket(sess->sock, sess->session);
	} while(1);

	if (!sess->channel) {
		rc = libssh2_session_last_error(sess->session, &err, NULL, 0);
		DEBUG("libssh2 channel error: %d - %s", rc, err);
		return 1;
	}

	libssh2_channel_set_blocking(sess->channel, 1);

	char *term_list[] = {"xterm-color", "vt100", "linux", "xterm", "xterm-256color", "linux", "ansi", "vanilla", NULL};
	char **term = term_list;

	if (opt_ssh_term) term = &opt_ssh_term; // redefine if has in cli

	while (*term) {
		rc = libssh2_channel_request_pty(sess->channel, *term);
		if (rc == 0) {
			DEBUG("%s pty %s on %s@%s","Successfully requested",
				*term, sess->user, sess->server_ip);
			libssh2_channel_setenv(sess->channel, "TERM", *term);
			break;
		}
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			DEBUG("%s pty %s on %s@%s","Get EAGAIN while request",
				*term, sess->user, sess->server_ip);
			ssh_waitsocket(sess->sock, sess->session);
			continue;
		} else if (rc < 0) {
			DEBUG("%s pty %s on %s@%s","Failed requesting",
				*term, sess->user, sess->server_ip);
			rc = libssh2_session_last_error(sess->session, &err, NULL, 0);
			DEBUG("libssh2 error: %d - %s", rc, err);
		}
		if (opt_ssh_term) break; // don't try other values if defined in cli
		term++;
	} // while term

	if (*term == NULL) {
		DEBUG("Can't found any pty type on SSH %s@%s", sess->user, sess->server_ip);
		return 1;
	}

	// Apply PTY size if not default
	if (
		sess->pty_cols != LIBSSH2_TERM_WIDTH
		|| sess->pty_rows != LIBSSH2_TERM_HEIGHT
	) {
		rc = libssh2_channel_request_pty_size(sess->channel,
			sess->pty_cols, sess->pty_rows);
		if (rc == 0) {
			DEBUG("Change pty size on %s@%s to %d x %d",
				sess->user, sess->server_ip,
				sess->pty_cols, sess->pty_rows);
		}
	}

	libssh2_channel_set_blocking(sess->channel, 1);

	while(1) {
		rc = libssh2_channel_shell(sess->channel);
		if (rc == 0) {
			DEBUG("Successfully requested shell on %s@%s", sess->user, sess->server_ip);
			break;
		}
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			DEBUG("Get EAGAIN while requested shell on %s@%s", sess->user, sess->server_ip);
			ssh_waitsocket(sess->sock, sess->session);
			continue;
		} else if (rc < 0) {
			DEBUG("Unable to request shell on allocated channel %s@%s", sess->user, sess->server_ip);
			rc = libssh2_session_last_error(sess->session, &err, NULL, 0);
			DEBUG("libssh2 error: %d - %s", rc, err);
			return 1;
		}
	}

	libssh2_channel_set_blocking(sess->channel, 0);

	DEBUG("Up ssh channel successful %s@%s:%d", sess->user, sess->server_ip, sess->port);
	sess->ssh_state = 1; // work

	return 0;
} // up_ssh_channel()


static void web_proxy_cb(struct evhttp_request *req, void *arg)
{
	FILE *f = NULL;
	int http_err_code = HTTP_INTERNAL;
	unsigned long uuid[5];
	char info_path[5 * 4 * 2 + 5 + 15];
	char prikey_path[5 * 4 * 2 + 5 + 15];
	char pubkey_path[5 * 4 * 2 + 5 + 15];
	char buf[256];
	int rc;

//	// Don't log any full URI (it has password in plain text) !!!
//	DEBUG("[%s]: %s", req->remote_host, req->uri);

	const char *uri = evhttp_request_get_uri(req);
	char *q_uuid = NULL;
	char *q_user = NULL;
	char *q_pass = NULL;
	int q_cols = 0;
	int q_rows = 0;
	int q_record = 1;
	struct proxy_session *ps = NULL;
	evutil_socket_t fd;
	struct sockaddr_storage addr;
	socklen_t len;

	// Check GET variables
	struct evkeyvalq get_vars;
	if (uri && evhttp_parse_query(req->uri, &get_vars) == 0) {
		const char *v;
		if ((v = evhttp_find_header(&get_vars, "uuid")) != NULL) q_uuid = strdup(v);
		if ((v = evhttp_find_header(&get_vars, "user")) != NULL) q_user = strdup(v);
		if ((v = evhttp_find_header(&get_vars, "pass")) != NULL) q_pass = strdup(v);
		if ((v = evhttp_find_header(&get_vars, "norec")) != NULL) q_record = 0;
		if ((v = evhttp_find_header(&get_vars, "cols")) != NULL) q_cols = atoi(v);
		if ((v = evhttp_find_header(&get_vars, "rows")) != NULL) q_rows = atoi(v);
	};
	evhttp_clear_headers(&get_vars);

	if (!q_uuid || !q_user || !q_pass) {
		DEBUG("Not found user, pass or uuid in request from %s", req->remote_host);
		http_err_code = HTTP_BADREQUEST; goto err;
	}

	// Check UUID
	if (5 != sscanf(q_uuid,"%lx-%lx-%lx-%lx-%lx",&uuid[0],&uuid[1],&uuid[2],&uuid[3],&uuid[4])) {
		http_err_code = HTTP_BADREQUEST; goto err;
	}

	// Check SSH session files
	sprintf(info_path, DIR_UUID_FORMAT, opt_tmp_dir,
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], "sshws");
	if (access(info_path, R_OK) != 0) {
		DEBUG("Can't found file %s", info_path);
		http_err_code = HTTP_NOTFOUND;
		goto err;
	}

	sprintf(prikey_path, DIR_UUID_FORMAT, opt_tmp_dir,
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], "pri");
	if (access(prikey_path, W_OK | R_OK) != 0) {
		DEBUG("Can't found file %s", prikey_path);
		http_err_code = HTTP_NOTFOUND;
		goto err;
	}

	sprintf(pubkey_path, DIR_UUID_FORMAT, opt_tmp_dir,
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], "pub");
	if (access(pubkey_path, W_OK | R_OK) != 0) {
		DEBUG("Can't found file %s", pubkey_path);
		http_err_code = HTTP_NOTFOUND;
		goto err;
	}

	f = fopen(info_path,"r");
	if (!f) {
		DEBUG("Can't open file %s",info_path);
		goto err;
	}

	// first line SSH server "IP:PORT"
	if (!fgets(buf, sizeof(buf), f)) {
		DEBUG("Can't read file sshws line");
		goto err;
	}
	char *p = strchr(buf, ':');
	if (!p) {
		DEBUG("Can't found port separator char ':' in [%s]", buf);
		goto err;
	};

	// Prepare proxy session struct
	ps = calloc(1, sizeof(struct proxy_session));
	if (!ps) {
		DEBUG("Can't allocate memory for session");
		goto err;
	}

	pthread_mutex_init(&ps->mutex,NULL);
	ps->user = q_user; q_user = NULL;
	ps->keypass = q_pass; q_pass = NULL;
	ps->record = q_record;
	ps->port = atoi(p+1);
	*p = '\0';
	ps->server_ip = strdup(buf);
	ps->pubkey = strdup(pubkey_path);
	ps->prikey = strdup(prikey_path);
	memcpy(&ps->uuid, &uuid, sizeof(uuid));
	ps->pty_cols = (q_cols > 0) ? q_cols : LIBSSH2_TERM_WIDTH;
	ps->pty_rows = (q_rows > 0) ? q_rows : LIBSSH2_TERM_HEIGHT;

	// second line client IP to allow connection
	if (!fgets(buf, sizeof(buf), f)) {
		DEBUG("Can't read file sshws line");
		goto err;
	}

	fclose(f); f = NULL;

	if (-1 == remove(info_path)) {
		DEBUG("Can't remove file %s - %s", info_path, strerror(errno));
	};

	// Create SSH session
	if (0 != up_ssh_session(ps)) {
		DEBUG("Failed to create ssh session");
		goto err;
	}

	if (0 != up_ssh_channel(ps)) {
		DEBUG("Failed to create ssh channel");
		goto err;
	}

	// Start thread
	rc = pthread_create(&ps->th, NULL, ssh_session_read_thread, (void *)ps);
	if (rc != 0) {
		DEBUG("Unable create pthread for %s@%s:%d", ps->user, ps->server_ip, ps->port);
		goto err;
	}
	DEBUG("Start ssh channel thread for %s@%s:%d", ps->user, ps->server_ip, ps->port);

/*
	// TODO join or detach ?!
	rc = pthread_detach(ps->th);
	if (rc != 0) {
		DEBUG("Can't detach pthread for %s@%s:%d", sess->user, sess->server_ip, sess->port);
		return 1;
	}
*/

	// Add to list
	pthread_mutex_lock(&proxy_session_list_mutex);
		ps->next = proxy_session_list;
		if (proxy_session_list) proxy_session_list->prev = ps;
		proxy_session_list = ps;
	pthread_mutex_unlock(&proxy_session_list_mutex);

	// Create WebSocket
	ps->evws = evws_new_session(req, websocket_msg_cb, ps, 0);
	if (!ps->evws) {
		DEBUG("Failed to create websocket session");
		goto err;
	}

	fd = bufferevent_getfd(evws_connection_get_bufferevent(ps->evws));

	len = sizeof(addr);
	getpeername(fd, (struct sockaddr *)&addr, &len);
	addr2str((struct sockaddr *)&addr, ps->name, sizeof(ps->name));

	evws_connection_set_closecb(ps->evws, websocket_close_cb, ps);

	size_t l = strlen(buf);
	while (l-1 > 0 && isspace(buf[l-1])) { buf[l-1] = 0; l--; } // trim right
	if (strncmp(ps->name, buf, l) == 0 && ps->name[l] == ':') {
		DEBUG("New client joined from [%s]", ps->name);
		ps->websocket_state = 1; // work
	} else {
		DEBUG("Unknown client [%s] try connect, need [%s], drop connection", ps->name, buf);
		ps->websocket_state = 2; // close websocket
		evws_close(ps->evws, WS_CR_NORMAL);
	}

	goto exit;
err:
	evhttp_send_error(req, http_err_code, NULL);
	if (ps) {
		clean_proxy_session(ps);
		free(ps);
	}

exit:
	if (q_uuid) free(q_uuid);
	if (q_user) free(q_user);
	if (q_pass) free(q_pass);
	if (f) fclose(f);

	// Garbage cleaner
	pthread_mutex_lock(&proxy_session_list_mutex);
	if (proxy_session_list) {
		struct proxy_session *s = proxy_session_list;
		while (s) {
			struct proxy_session *o = NULL;
			if (s->websocket_state == 2 && s->ssh_state == 2) {
				o = s;
				if (!s->prev)
					proxy_session_list = s->next;
				else
					s->prev->next = s->next;
				if (s->next) s->next->prev = s->prev;
			}
			s = s->next;
			if (o) {
				DEBUG("Clean memory from garbage session");
				free(o);
			}
		}
	}
	pthread_mutex_unlock(&proxy_session_list_mutex);
} // web_proxy_cb()


static void
web_root_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb;

	evhttp_add_header(
		evhttp_request_get_output_headers(req), "Content-Type", "text/plain");

	evb = evbuffer_new();
	if (!evb) goto err;

	evbuffer_add_printf(evb, "Hello %s\n", req->remote_host);
	evbuffer_add_printf(evb, "This is %s v%s\n", PROJECT_NAME, PROJECT_VERSION);
	evbuffer_add_printf(evb, "%s/%s\n", PROJECT_GIT, PROJECT_NAME);
	evhttp_send_reply(req, HTTP_OK, NULL, evb);
	evbuffer_free(evb);
	return;

err:
	evhttp_send_error(req, HTTP_NOTFOUND, NULL);
}

static void
web_status_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb;

	if (req->output_headers) {
		evhttp_add_header(req->output_headers, "Content-Type", "text/html");
		evhttp_add_header(req->output_headers, "Expires", "Mon, 01 Jan 1995 00:00:00 GMT");
		evhttp_add_header(req->output_headers, "Cache-Control", "no-cache, must-revalidate");
		evhttp_add_header(req->output_headers, "Pragma", "no-cache");
		evhttp_add_header(req->output_headers, "Refresh", "10");
	}

	evb = evbuffer_new();
	if (!evb) goto err;

	evbuffer_add_printf(evb, "<html><body>");
	evbuffer_add_printf(evb, "<h3>%s v%s</h3>", PROJECT_NAME, PROJECT_VERSION);

	evbuffer_add_printf(evb, "<p>Your IP: %s<br>", req->remote_host);

	evbuffer_add_printf(evb, "<p><b>Sessions</b>:<br><ol>");
	pthread_mutex_lock(&proxy_session_list_mutex);
	struct proxy_session *w = proxy_session_list;
	char buf[256];
	int c = 0;
	while (w) {
		evbuffer_add_printf(evb, "<li>");
		pthread_mutex_lock(&w->mutex);

		sprintf(buf, DIR_UUID_FORMAT, opt_tmp_dir,
			w->uuid[0], w->uuid[1], w->uuid[2],
			w->uuid[3], w->uuid[4],"sshtmp");

		evbuffer_add_printf(evb, "%s<br>%s@%s from %s",buf, w->user, w->server_ip, w->name);
		evbuffer_add_printf(evb, " SSH_");
		switch (w->ssh_state) {
			case 0: evbuffer_add_printf(evb, "UNKNOWN"); break;
			case 1: evbuffer_add_printf(evb, "OK"); break;
			case 2: evbuffer_add_printf(evb, "CLOSED"); break;
		}

		evbuffer_add_printf(evb, " WS_");
		switch (w->websocket_state) {
			case 0: evbuffer_add_printf(evb, "UNKNOWN"); break;
			case 1: evbuffer_add_printf(evb, "OK"); break;
			case 2: evbuffer_add_printf(evb, "CLOSED"); break;
		}

		evbuffer_add_printf(evb, " ssh %ld bytes", w->ssh_to_ws);
		evbuffer_add_printf(evb, ", ws %ld bytes", w->ws_to_ssh);

		pthread_mutex_unlock(&w->mutex);
		evbuffer_add_printf(evb, "</li>");
		c++;
		w = w->next;
	}
	pthread_mutex_unlock(&proxy_session_list_mutex);
	evbuffer_add_printf(evb, "</ol>");
	if (c == 0) evbuffer_add_printf(evb, "No active sessions");
	evbuffer_add_printf(evb, "</p>");
	evbuffer_add_printf(evb, "<p><a href=%s/%s target=_blank>%s/%s</a>"
		, PROJECT_GIT, PROJECT_NAME
		, PROJECT_GIT, PROJECT_NAME);
	evbuffer_add_printf(evb, "<br>License: MIT %s</p>", PROJECT_DATE);
	evbuffer_add_printf(evb, "</body></html>");
	evhttp_send_reply(req, HTTP_OK, NULL, evb);
	evbuffer_free(evb);
	return;

err:
	evhttp_send_error(req, HTTP_INTERNAL, NULL);
}


/*
#ifndef EVENT__HAVE_STRSIGNAL
static inline const char *
strsignal(evutil_socket_t sig)
{
	return "Signal";
}
#endif
*/
static void
signal_cb(evutil_socket_t fd, short event, void *arg)
{
	DEBUG("%s signal received", strsignal(fd));
	event_base_loopbreak(arg);
	terminate = 1;
}


void print_help(const char *prog) {
	printf("%s (v%s) SSH via WebSocket proxy\n", PROJECT_NAME, PROJECT_VERSION);
	printf("Kuzin Andrey (%s) MIT - %s/%s\n", PROJECT_DATE, PROJECT_GIT, PROJECT_NAME);
	printf("libevent version: \"%s\"\n",event_get_version());
	printf("OpenSSL version: \"%s\"\n",SSLeay_version(SSLEAY_VERSION));
	printf("libssh2 version: \"%s\"\n",LIBSSH2_VERSION);
	printf("\nUsage: %s [options]\n", prog);
	printf("\t-f - foreground mode (daemonize by default)\n");
	printf("\t-l <ip> - listening IP (default: \"%s\")\n", opt_server_bind);
	printf("\t-p <port> - listening port (default: %d)\n", opt_server_port);
	printf("\t-k - insecure HTTP mode\n");
	printf("\t-a <fullchain.pem> - fullchain SSL cert PEM file (default: \"%s\")\n",opt_cert_full_chain);
	printf("\t-b <primary> - primary SSL cert PEM file (default: \"%s\")\n",opt_cert_primary);
	printf("\t-x <termtype> - SSH PTY terminal type (ex. xterm-color, ansi, vt100 ...)\n");
	printf("\t-t <tmp_dir> - temporary files dir (default: \"%s\")\n", opt_tmp_dir);
	printf("\t-r <records_dir> - dir for save records (default: \"%s\")\n", opt_records_dir);
	exit(0);
} // print_help()


int
main(int argc, char **argv)
{
	SSL_CTX *ctx = NULL;
	struct proxy_session *s;

	// Parse program options
	int opt = 0;
	while ( (opt = getopt(argc, argv, "hfl:p:ka:b:x:t:r:")) != -1)
	switch (opt) {
		case 'h': print_help(argv[0]); break;
		case 'f': opt_foreground = 1; break;
		case 'l': opt_server_bind = optarg; break;
		case 'p': opt_server_port = atoi(optarg); break;
		case 'k': opt_use_ssl = 0; break;
		case 'a': opt_cert_full_chain = optarg; break;
		case 'b': opt_cert_primary = optarg; break;
		case 'x': opt_ssh_term = optarg; break;
		case 't': opt_tmp_dir = optarg; break;
		case 'r': opt_records_dir = optarg; break;
		case '?':
			fprintf(stderr,"Unknown option: %c\n", optopt);
			return 1;
			break;
	}; // switch

	if (-1 == access(opt_cert_full_chain, F_OK)) {
		fprintf(stderr, "ERROR: can't find file %s\n", opt_cert_full_chain);
		return 1;
	}

	if (-1 == access(opt_cert_primary, F_OK)) {
		fprintf(stderr, "ERROR: can't find file %s\n", opt_cert_primary);
		return 1;
	}

	if (opt_server_port == 0) {
		fprintf(stderr, "ERROR: listening port can't be zero or parse failure\n");
		return 1;
	}

	// TODO check directories opt_tmp_dir, opt_records_dir for existance

	openlog(argv[0], LOG_PID, LOG_DAEMON);

	DEBUG("libevent version: \"%s\"",event_get_version());

	// Init OpenSSL
	if (opt_use_ssl) {
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_all_algorithms();
		DEBUG("OpenSSL version: \"%s\"",SSLeay_version(SSLEAY_VERSION));
	}

	base = event_base_new();
	if (!base) {
		DEBUG("Can't create event_base");
		return 1;
	}

	http_server = evhttp_new(base);
		if (!http_server) {
		DEBUG("Can't create evhttp");
		return 1;
	}

	// Init OpenSSL TLS context
	if (opt_use_ssl) {
		ctx = SSL_CTX_new (TLS_server_method());
		if (!ctx) DIE_OPENSSL("SSL_CTX_new");

		if (1 != SSL_CTX_use_certificate_chain_file(ctx, opt_cert_full_chain))
			DIE_OPENSSL("SSL_CTX_use_certificate_chain_file");

		if (1 != SSL_CTX_use_PrivateKey_file(ctx, opt_cert_primary, SSL_FILETYPE_PEM))
			DIE_OPENSSL("SSL_CTX_use_PrivateKey_file");

		if (1 != SSL_CTX_check_private_key(ctx))
			DIE_OPENSSL("SSL_CTX_check_private_key");
	}

	if (!evhttp_bind_socket_with_handle(http_server, opt_server_bind, opt_server_port)) {
		DEBUG("Can't bind to port %d", opt_server_port);
	}

	if (opt_use_ssl) {
		evhttp_set_bevcb(http_server, bevcb, ctx); // magic for use SSL in evhttp
	}

	evhttp_set_cb(http_server, "/", web_root_cb, NULL);
	evhttp_set_cb(http_server, "/proxy", web_proxy_cb, NULL);
	evhttp_set_cb(http_server, "/status", web_status_cb, NULL);

	DEBUG("%s server start listening on %s:%d ...", argv[0], opt_server_bind, opt_server_port);

	if (!opt_foreground) {
		if (daemon(0, 0) != 0) {
			fprintf(stderr,"Can't daemonize process!\n");
			goto exit;
		};
	}

	sig_int = evsignal_new(base, SIGINT, signal_cb, base);
	event_add(sig_int, NULL);
	sig_term = evsignal_new(base, SIGTERM, signal_cb, base);
	event_add(sig_term, NULL);

	event_base_dispatch(base);
	evhttp_free(http_server);
exit:
	terminate = 1;

	event_free(sig_int);
	event_base_free(base);

	if (opt_use_ssl) {
		SSL_CTX_free(ctx);
		EVP_cleanup();
	}

	libevent_global_shutdown();

	// wait for terminate threads
	s = proxy_session_list;
	while (s) {
		pthread_join(s->th, NULL);
		s = s->next;
	}

	DEBUG("%s exiting", argv[0]);
	closelog();
	return 0;
}
