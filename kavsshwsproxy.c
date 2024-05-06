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
///////////////////////////////////////////////////////
*/

#define PROJECT_NAME "kavsshwsproxy"
#define PROJECT_VERSION "0.1"
#define PROJECT_DATE "2024-05-06"
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

// #define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#define DEBUG(...) syslog(LOG_INFO | LOG_PID, __VA_ARGS__);

#define DIE_OPENSSL(name) { fprintf(stderr, \
	"ERROR: openssl function %s (%s:%d)\n", \
	name, __FILE__, __LINE__); \
	ERR_print_errors_fp(stderr); \
	exit(EXIT_FAILURE); }

#define TMP_DIR_UUID_FORMAT "/tmp/%08lx-%04lx-%04lx-%04lx-%012lx.%s"

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

struct proxy_session {
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
	int ssh_ok;

	struct evws_connection *evws;
	char name[INET6_ADDRSTRLEN];
	int websocket_ok;

	unsigned long uuid[5];
	int record;
	char *record_name;
	gzFile record_fd;
	pthread_mutex_t gzmutex;
};

// Call back for incoming websocket data write to ssh channel
static void
websocket_msg_cb(struct evws_connection *evws, int type, const unsigned char *data,
	size_t len, void *arg)
{
	struct proxy_session *self = arg;
	struct timeval curtime = {0};

	if (!self->ssh_ok) return;

	ssize_t n;
	size_t pos = 0;
	do {
		n = libssh2_channel_write(self->channel,(const char *) data + pos, len - pos);
		if (n == LIBSSH2_ERROR_EAGAIN) continue;
		else if (n < 0) break;
		pos += n;

		if (self->record && self->record_fd) {
			pthread_mutex_lock(&self->gzmutex);
			gettimeofday(&curtime, NULL);
			gzwrite(self->record_fd, &curtime, sizeof(struct timeval));
			gzwrite(self->record_fd,">>",3);
			gzwrite(self->record_fd, &n, sizeof(n));
			gzwrite(self->record_fd, data + pos, len - pos);
			pthread_mutex_unlock(&self->gzmutex);
		}
	} while (len - pos > 0);
} // websocket_msg_cb()

static void
websocket_close_cb(struct evws_connection *evws, void *arg)
{
	struct proxy_session *client = arg;
	DEBUG("WebSocket '%s' disconnected", client->name);
	client->websocket_ok = 0;
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
	char buf[1024];
	size_t s;
	struct timeval curtime = {0};

	pthread_mutex_init(&self->gzmutex,NULL);

	if (self->record) {
		pthread_mutex_lock(&self->gzmutex);
		sprintf(buf, TMP_DIR_UUID_FORMAT,
			self->uuid[0], self->uuid[1], self->uuid[2],
			self->uuid[3], self->uuid[4],"sshtmp");
		self->record_fd = gzopen(buf,"w");
		if (self->record_fd) {
			self->record_name = strdup(buf);
			gettimeofday(&curtime, NULL);
			gzwrite(self->record_fd, REC_HEADER_SIGN, strlen(REC_HEADER_SIGN) + 1);
			gzwrite(self->record_fd, PROJECT_NAME, sizeof(PROJECT_NAME));
			gzwrite(self->record_fd, PROJECT_VERSION, sizeof(PROJECT_VERSION));
			gzwrite(self->record_fd, self->server_ip, strlen(self->server_ip) + 1);
			gzwrite(self->record_fd, &self->port, sizeof(self->port));
			gzwrite(self->record_fd, self->name, strlen(self->name) + 1);
			gzwrite(self->record_fd, self->user, strlen(self->user) + 1);
			gzwrite(self->record_fd, self->uuid, sizeof(self->uuid));
			s = sizeof(struct timeval);
			gzwrite(self->record_fd, &s, sizeof(s));
			gzwrite(self->record_fd, &curtime, sizeof(struct timeval));
		}
		pthread_mutex_unlock(&self->gzmutex);
	}

	while (self->websocket_ok == 0) {};

	while(!libssh2_channel_eof(self->channel) && self->websocket_ok == 1) {
		ssize_t len = libssh2_channel_read(self->channel, buf, sizeof(buf));
		if(len < 0) {
			if (LIBSSH2_ERROR_EAGAIN == len) {
				ssh_waitsocket(self->sock, self->session);
				continue;
			}
			DEBUG( "Unable to read response from %s:%d - %ld", self->server_ip, self->port, (long)len);
			break;
		} else {
			if (self->websocket_ok == 1 && self->evws) {
				evws_send_binary(self->evws, buf, len);
				if (self->record && self->record_fd) {
					pthread_mutex_lock(&self->gzmutex);
					gettimeofday(&curtime, NULL);
					gzwrite(self->record_fd, &curtime, sizeof(struct timeval));
					gzwrite(self->record_fd,"<<",3);
					gzwrite(self->record_fd, &len, sizeof(len));
					gzwrite(self->record_fd, buf, len);
					pthread_mutex_unlock(&self->gzmutex);
				}
			} else break;
		}
	} // while
	self->ssh_ok = 0;

	sleep(1); // stupid sync
	DEBUG("Thread clean %s@%s:%d -> WS %s",self->user,self->server_ip,self->port, self->name);
	if (self->websocket_ok == 1 && self->evws) {
		DEBUG("Thread websocket close %s", self->name);
		evws_close(self->evws, WS_CR_NORMAL);
	}

	clean_ssh_channel(self);
	clean_proxy_session(self);
	sleep(1); // stupid sync
	if (self->record_fd) {
		gzclose(self->record_fd);
		if (self->record_name) {
			sprintf(buf, TMP_DIR_UUID_FORMAT,
				self->uuid[0], self->uuid[1], self->uuid[2],
				self->uuid[3], self->uuid[4],"sshproxyrec.gz");
			if (-1 == rename(self->record_name, buf)) {
				DEBUG("Can't rename %s to %s", self->record_name, buf);
			}
		}
	}
	if (self->record_name) {
		free(self->record_name);
		self->record_name = NULL;
	}
	free(self);
//	DEBUG("Thread exit");
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
		DEBUG("Can't found any pty type on SSH");
		return 1;
	}

	// Apply PTY size if defined
	if (sess->pty_cols > 0 || sess->pty_rows > 0) {
		int w = LIBSSH2_TERM_WIDTH;
		int h = LIBSSH2_TERM_HEIGHT;
		if (sess->pty_cols > 0) w = sess->pty_cols;
		if (sess->pty_rows > 0) h = sess->pty_rows;
		rc = libssh2_channel_request_pty_size(sess->channel, w, h);
		if (rc == 0) {
			DEBUG("Change pty size on %s@%s to %d x %d", sess->user, sess->server_ip, w, h);
		}
	}

	libssh2_channel_set_blocking(sess->channel, 1);

	while(1) {
		rc = libssh2_channel_shell(sess->channel);
		if (rc == 0) {
			DEBUG("Successfully requested shell");
			break;
		}
		if (rc == LIBSSH2_ERROR_EAGAIN) {
			DEBUG("Get EAGAIN while requested shell");
			ssh_waitsocket(sess->sock, sess->session);
			continue;
		} else if (rc < 0) {
			DEBUG("Unable to request shell on allocated channel");
			rc = libssh2_session_last_error(sess->session, &err, NULL, 0);
			DEBUG("libssh2 error: %d - %s", rc, err);
			return 1;
		}
	}

	libssh2_channel_set_blocking(sess->channel, 0);

	DEBUG("Up ssh channel successful %s@%s:%d", sess->user, sess->server_ip, sess->port);
	sess->ssh_ok = 1;

	pthread_t th;
	rc = pthread_create(&th, NULL, ssh_session_read_thread, (void *)sess);
	if (rc != 0) {
		DEBUG("Unable create pthread for %s@%s:%d", sess->user, sess->server_ip, sess->port);
		return 1;
	}

	rc = pthread_detach(th);
	if (rc != 0) {
		DEBUG("Can't detach pthread for %s@%s:%d", sess->user, sess->server_ip, sess->port);
		return 1;
	}

	DEBUG("Start ssh channel thread for %s@%s:%d", sess->user, sess->server_ip, sess->port);

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
	sprintf(info_path,TMP_DIR_UUID_FORMAT,uuid[0],uuid[1],uuid[2],uuid[3],uuid[4], "sshws");
	if (access(info_path, R_OK) != 0) {
		DEBUG("Can't found file %s", info_path);
		http_err_code = HTTP_NOTFOUND;
		goto err;
	}

	sprintf(prikey_path,TMP_DIR_UUID_FORMAT,uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],"pri");
	if (access(prikey_path, W_OK | R_OK) != 0) {
		DEBUG("Can't found file %s", prikey_path);
		http_err_code = HTTP_NOTFOUND;
		goto err;
	}

	sprintf(pubkey_path,TMP_DIR_UUID_FORMAT,uuid[0],uuid[1],uuid[2],uuid[3],uuid[4],"pub");
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
	ps->user = q_user; q_user = NULL;
	ps->keypass = q_pass; q_pass = NULL;
	ps->record = q_record;
	ps->port = atoi(p+1);
	*p = '\0';
	ps->server_ip = strdup(buf);
	ps->pubkey = strdup(pubkey_path);
	ps->prikey = strdup(prikey_path);
	memcpy(&ps->uuid, &uuid, sizeof(uuid));
	if (q_cols > 0) ps->pty_cols = q_cols;
	if (q_rows > 0) ps->pty_rows = q_rows;

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
		ps->websocket_ok = 1;
	} else {
		DEBUG("Unknown client [%s] try connect, need [%s], drop connection", ps->name, buf);
		evws_close(ps->evws, WS_CR_NORMAL);
		ps->websocket_ok = 2; // exit websocket
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
	printf("\t-p <port> - ssh port (default: %d)\n", opt_server_port);
	printf("\t-k - insecure HTTP mode\n");
	printf("\t-a <fullchain.pem> - fullchain SSL cert PEM file (default: \"%s\")\n",opt_cert_full_chain);
	printf("\t-b <primary> - primary SSL cert PEM file (default: \"%s\")\n",opt_cert_primary);
	printf("\t-x <termtype> - SSH PTY terminal type (ex. xterm-color, ansi, vt100 ...)\n");
	exit(0);
} // print_help()


int
main(int argc, char **argv)
{
	SSL_CTX *ctx = NULL;

	// Parse program options
	int opt = 0;
	while ( (opt = getopt(argc, argv, "hfl:p:ka:b:x:")) != -1)
	switch (opt) {
		case 'h': print_help(argv[0]); break;
		case 'f': opt_foreground = 1; break;
		case 'l': opt_server_bind = optarg; break;
		case 'p': opt_server_port = atoi(optarg); break;
		case 'k': opt_use_ssl = 0; break;
		case 'a': opt_cert_full_chain = optarg; break;
		case 'b': opt_cert_primary = optarg; break;
		case 'x': opt_ssh_term = optarg; break;
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
	//TODO status page

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
	event_free(sig_int);
	event_base_free(base);

	if (opt_use_ssl) {
		SSL_CTX_free(ctx);
		EVP_cleanup();
	}

	libevent_global_shutdown();

	// TODO terminate detached threads and wait for close ?!

	DEBUG("%s exiting", argv[0]);
	closelog();
	return 0;
}
