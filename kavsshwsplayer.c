/*
///////////////////////////////////////////////////////
kavsshwsplayer - SSH via WebSocket proxy records player

Author: kuzinandrey@yandex.ru
URL: https://www.github.com/KuzinAndrey/kavsshwsproxy
License: MIT
///////////////////////////////////////////////////////
Dependency:
    libevent - Event notification library (with WebSocket support !!!)
    zlib - general compession library 1.2.11

History:
    2024-05-11 - Initial version
    2024-05-17 - Add /skip for skip long delays
///////////////////////////////////////////////////////
*/

#define PROJECT_NAME "kavsshwsproxy"
#define PROJECT_SUBNAME "kavsshwsplayer"
#define PROJECT_VERSION "0.2"
#define PROJECT_DATE "2024-05-17"
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
#include <json-c/json.h>

#include <zlib.h>

#define OPENSSL_NO_DEPRECATED_3_0
#include <openssl/ssl.h>
#include <openssl/err.h>

#define DEBUG(...) { fprintf(stderr, __VA_ARGS__); fprintf(stderr,"\n"); }
//#define DEBUG(...) syslog(LOG_INFO | LOG_PID, __VA_ARGS__);

#define DIE_OPENSSL(name) { fprintf(stderr, \
	"ERROR: openssl function %s (%s:%d)\n", \
	name, __FILE__, __LINE__); \
	ERR_print_errors_fp(stderr); \
	exit(EXIT_FAILURE); }

#define RECORD_UUID_FORMAT "%s/%08lx-%04lx-%04lx-%04lx-%012lx.%s"

// Libevent global objects
struct event_base *base;
struct event *sig_int;
struct event *sig_term;
struct evhttp *http_server;

// Options from cli
char *opt_server_bind = "0.0.0.0";
int opt_server_port = 6971;
int opt_use_ssl = 1;
int opt_foreground = 0;
char *opt_records_dir = "/tmp/records";
char *opt_records_suffix = "sshproxyrec.gz";
char *opt_cert_full_chain = "fullchain.pem";
char *opt_cert_primary = "prikey.pem";

struct proxy_player {
	pthread_t th;
	pthread_mutex_t mutex;
	struct proxy_player *next;
	struct proxy_player *prev;

	// Record
	unsigned long uuid[5];
	char *encrypt_pass;

	char *user;
	char *server_ip;
	in_port_t port;
	int pty_cols;
	int pty_rows;

	struct timeval start_time;
	struct timeval position;
	struct timeval end_time;

	int play_mode; // 0 - stop, 1 - play
	int play_speed; // 0 - rewind, 1 - normal, N - speed_up
	int skip_mode;

	int websocket_state; // 0 - new, 1 - ok, 2 - closed
	struct evws_connection *evws;
	char name[INET6_ADDRSTRLEN];

	FILE *hist;
};

static pthread_mutex_t proxy_player_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct proxy_player *proxy_player_list = NULL;
int terminate = 0;

// Call back for incoming websocket command
static void
websocket_msg_cb(struct evws_connection *evws, int type, const unsigned char *data,
	size_t len, void *arg)
{
	struct proxy_player *self = arg;
//	struct timeval curtime = {0};

	char buf[4096];
	const char *msg = (const char *)data;

	snprintf(buf, sizeof(buf), "%.*s", (int)len, msg);
	DEBUG("WS: %s",buf);

	if (len == 5 && memcmp(buf, "/stop", 5) == 0) {
		DEBUG("'%s' want to quit", self->name);
		evws_close(evws, WS_CR_NORMAL);
	} else if (len == 6 && strncmp(msg, "/pause", 6) == 0) {
		DEBUG("'%s' want to pause", self->name);
		self->play_mode = 0;
	} else if (len == 5 && strncmp(msg, "/play", 5) == 0) {
		DEBUG("'%s' want to play", self->name);
		self->play_mode = 1;
	} else if (len == 5 && strncmp(msg, "/skip", 5) == 0) {
		DEBUG("'%s' want to skip", self->name);
		self->skip_mode = 1;
	}
} // websocket_msg_cb()

static void
websocket_close_cb(struct evws_connection *evws, void *arg)
{
	struct proxy_player *self = arg;
	pthread_mutex_lock(&self->mutex);
		DEBUG("WebSocket player '%s' disconnected", self->name);
		self->websocket_state = 2; // closed
	pthread_mutex_unlock(&self->mutex);
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

const char base64[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/";

size_t base64_encode(const void *buf, size_t size, void *enc, size_t esize)
{
	size_t ret = 0;
	size_t rem = size;
	const unsigned char *p = buf;
	unsigned char *o = enc;
	esize -= 1; // '0' space

	while (rem >= 3 && esize >= 4) {
		*o++ = base64[p[0] >> 2];
		*o++ = base64[((p[0] & 0x03) << 4) | (p[1] >> 4)];
		*o++ = base64[((p[1] & 0x0F) << 2) | (p[2] >> 6)];
		*o++ = base64[p[2] & 0x3F];
		p += 3;
		rem -= 3;
		ret += 4;
		esize -= 4;
	}
	if (rem > 0 && esize >= 4) {
		*o++ = base64[p[0] >> 2];
		if (rem == 1) {
			*o++ = base64[(p[0] & 0x03) << 4];
			*o++ = '=';
		} else {
			*o++ = base64[((p[0] & 0x03) << 4) | (p[1] >> 4)];
			*o++ = base64[(p[1] & 0x0F) << 2];
		}
		*o++ = '=';
		ret += 4;
	}
	*o = '\0';

	return ret;
}

// callback for creating new SSL connection wrapped in OpenSSL bufferevent
static struct bufferevent *bevcb(struct event_base *base, void *arg) {
	struct bufferevent *r;
	SSL_CTX *ctx = (SSL_CTX *)arg;
	r = bufferevent_openssl_socket_new(base, -1, SSL_new(ctx),
		BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
	return r;
} // bevcb()


void clean_proxy_player(struct proxy_player *sess) {
	if (!sess) return;
	if (sess->encrypt_pass) { free(sess->encrypt_pass); sess->encrypt_pass = NULL; }
	if (sess->user) { free(sess->user); sess->user = NULL; }
	if (sess->server_ip) { free(sess->server_ip); sess->server_ip = NULL; }
	if (sess->hist) { fclose(sess->hist); sess->hist = NULL; }
} // clean_proxy_player()

ssize_t read_string(FILE *f, char *buf, size_t size) {
	size_t r = 0;
	if (!f || !buf || !size) return -1;
	size -= 1; // preserve space of '\0' for string
	while (r < size) {
		buf[r] = fgetc(f);
		if (buf[r] == EOF || buf[r] == 0) break;
		r++;
	}
	buf[r] = 0;
	return r;
}

void *websocket_proxy_player_thread(void *data) {
	struct proxy_player *self = data;
	char buf[1024 * 32];
	char buf64[(sizeof(buf) * 8) / 6 + 10];
	char sbuf[10];
	unsigned long ruuid[5];
	ssize_t len = 0;
	size_t s;
	struct json_object *js = NULL;
	struct json_object *js_time = NULL;
	struct json_object *js_data = NULL;
	struct timeval tv;
	struct timespec req, rem;

	double d_start = 0.0;
	double d_prev = 0.0;
	double d_now = 0.0;
	double d_dt = 0.0;

	double real_start = 0.0;
	double real_prev = 0.0;
	double real_now = 0.0;
	double real_dt = 0.0;

	double dt = 0.0;

	// Add to list
	pthread_mutex_lock(&proxy_player_list_mutex);
		self->next = proxy_player_list;
		if (proxy_player_list) proxy_player_list->prev = self;
		proxy_player_list = self;
	pthread_mutex_unlock(&proxy_player_list_mutex);

	snprintf(buf, sizeof(buf), RECORD_UUID_FORMAT,
		opt_records_dir, self->uuid[0], self->uuid[1], self->uuid[2],
		self->uuid[3], self->uuid[4], opt_records_suffix);

	js = json_object_new_object();
	if (!js) goto exit_thread;
	js_time = json_object_new_double(0.0);
	if (!js_time) {
		json_object_put(js);
		goto exit_thread;
	}
	js_data = json_object_new_string("");
	if (!js_data) {
		json_object_put(js);
		json_object_put(js_time);
		goto exit_thread;
	}


	json_object_object_add(js, "time", js_time);
	json_object_object_add(js, "data", js_data);

	gzFile gz = gzopen(buf,"r");
	if (!gz) goto exit_thread;

	self->hist = tmpfile();
	if (!self->hist) {
		gzclose(gz);
		goto exit_thread;
	}

	while (!gzeof(gz)) {
		int rlen = gzread(gz, buf, sizeof(buf));
		if (rlen > 0) {
			if (rlen != fwrite(buf, 1, rlen, self->hist)) {
				DEBUG("Error write ungzipped history");
				gzclose(gz);
				goto exit_thread;
			}
		}
	}
	gzclose(gz);

	fseek(self->hist, 0, SEEK_SET);

	len = read_string(self->hist, buf, sizeof(buf));
	if (len > 0) {
		//DEBUG("read[%ld] = %s", len, buf);
		if (strcmp(buf, REC_HEADER_SIGN) != 0) goto exit_thread;

		len = read_string(self->hist, buf, sizeof(buf));
		// PROJECT_NAME
		// DEBUG("project: %s", buf);
		if (strcmp(buf, PROJECT_NAME) != 0) goto exit_thread;

		len = read_string(self->hist, buf, sizeof(buf));
		// PROJECT_VERSION
		// DEBUG("version: %s", buf);

		len = read_string(self->hist, buf, sizeof(buf));
		self->server_ip = strdup(buf);

		len = fread(&self->port, 1, sizeof(self->port), self->hist);
		// DEBUG("server ip: %s:%d", buf, self->port);

		len = read_string(self->hist, buf, sizeof(buf));
		// websession self->name
		// DEBUG("websession: %s", buf);

		len = read_string(self->hist, buf, sizeof(buf));
		self->user = strdup(buf);
		// DEBUG("user name: %s", buf);

		len = fread(ruuid, 1, sizeof(ruuid), self->hist);
		if (len != sizeof(ruuid)) goto exit_thread;

		len = fread(&self->pty_cols, 1, sizeof(self->pty_cols), self->hist);
		if (len != sizeof(self->pty_cols)) goto exit_thread;
		len = fread(&self->pty_rows, 1, sizeof(self->pty_rows), self->hist);
		if (len != sizeof(self->pty_rows)) goto exit_thread;

		len = fread(&s, 1, sizeof(size_t), self->hist);
		if (len != sizeof(size_t) || s != sizeof(struct timeval)) goto exit_thread;

		len = fread(&self->start_time, 1, sizeof(struct timeval), self->hist);
		if (len != sizeof(struct timeval)) goto exit_thread;
		DEBUG("time_start: %ld", self->start_time.tv_sec);

		d_start = self->start_time.tv_sec + self->start_time.tv_usec / 1000000.0;
		d_prev = d_start;

		gettimeofday(&tv, NULL);
		real_start =  tv.tv_sec + tv.tv_usec / 1000000.0;
		real_prev = real_start;
	} else goto exit_thread;

	while (0 == self->websocket_state) {};

	// send recond info in first packet
	struct json_object *info = json_object_new_object();
	if (info) {
		json_object_object_add(info,"info", json_object_new_boolean(1));
		snprintf(buf, sizeof(buf), "%08lx-%04lx-%04lx-%04lx-%012lx",
			self->uuid[0], self->uuid[1], self->uuid[2], self->uuid[3], self->uuid[4]);
		json_object_object_add(info,"uuid", json_object_new_string(buf));
		json_object_object_add(info,"server_ip", json_object_new_string(self->server_ip));
		json_object_object_add(info,"server_port", json_object_new_int(self->port));
		json_object_object_add(info,"user", json_object_new_string(self->user));
		json_object_object_add(info,"cols", json_object_new_int(self->pty_cols));
		json_object_object_add(info,"rows", json_object_new_int(self->pty_rows));
		evws_send_text(self->evws,json_object_to_json_string_ext(info, 0));
		json_object_put(info);
	}

	self->play_mode = 1;

	while (1 == self->websocket_state) {
		while (self->play_mode == 0) {
			sleep(1);
			continue;
		}

		len = fread(&tv, 1, sizeof(struct timeval), self->hist);
		len = fread(sbuf, 1, 3, self->hist);
		d_now = tv.tv_sec + tv.tv_usec / 1000000.0;

		len = fread(&s, 1, sizeof(size_t), self->hist);
		if (len != sizeof(size_t)) goto exit_thread;

		if (s > sizeof(buf)) {
			DEBUG("bigger size %ld", s);
			goto exit_thread;
		}
		len = fread(buf, 1, s, self->hist);
		if (len != s) goto exit_thread;

		base64_encode(buf, len, buf64, sizeof(buf64));

		gettimeofday(&tv, NULL);
		real_now =  tv.tv_sec + tv.tv_usec / 1000000.0;

		d_dt = d_now - d_prev;
		real_dt = real_now - real_prev;

		dt = d_dt - real_dt;
		if (dt > 0.0) {
			if (dt > 5) { // activate skip mode on frontend if delay bigger than 5 sec
				char skip[100];
				snprintf(skip,sizeof(skip),"{\"skip\":%.2f}",dt);
				evws_send_text(self->evws,skip);
			}
			while (dt > 1) {
				if (self->skip_mode) {
					self->skip_mode = 0;
					dt = dt - (dt / 1);
					break;
				}
				sleep(1);
				dt -= 1.0f;
			}
			req.tv_sec = dt / 1;
			req.tv_nsec = (dt - req.tv_sec * 1.0) * 1000000000.0;
			if (-1 == nanosleep(&req, &rem)) goto exit_thread;
		}

		d_prev = d_now;
		real_prev = real_now;

		if (strcmp(sbuf,"<<") == 0 && s > 0) {
			pthread_mutex_lock(&self->mutex);
			if (self->websocket_state == 1) {
				json_object_set_double(js_time, d_now - d_start);
				json_object_set_string(js_data, buf64);
				evws_send_text(self->evws,
					json_object_to_json_string_ext(js,
						JSON_C_TO_STRING_NOSLASHESCAPE
						| JSON_C_TO_STRING_PLAIN)
				);
			}
			pthread_mutex_unlock(&self->mutex);
		}
	} // while

exit_thread:
	if (self->websocket_state == 1) {
		evws_close(self->evws, WS_CR_NORMAL);
		sleep(1);
	};

	// remove from list
	pthread_mutex_lock(&proxy_player_list_mutex);
	if (!self->prev)
		proxy_player_list = self->next;
	else
		self->prev->next = self->next;
	if (self->next) self->next->prev = self->prev;
	pthread_mutex_unlock(&proxy_player_list_mutex);

	clean_proxy_player(self);
	free(self);

	if (js) json_object_put(js);

	DEBUG("Exit pthread");

	pthread_exit(NULL);

} // websocket_proxy_player_thread()


static void web_play_cb(struct evhttp_request *req, void *arg)
{
	int http_err_code = HTTP_INTERNAL;
	unsigned long uuid[5];
	int rc;

	// Don't log any full URI (it has password in plain text) !!!
	// DEBUG("[%s]: %s", req->remote_host, req->uri);

	const char *uri = evhttp_request_get_uri(req);
	char *q_uuid = NULL;
	char *q_pass = NULL;
	char record_path[PATH_MAX];

	struct proxy_player *pp = NULL;
	evutil_socket_t fd;
	struct sockaddr_storage addr;
	socklen_t len;

	// Check GET variables
	struct evkeyvalq get_vars;
	if (uri && evhttp_parse_query(req->uri, &get_vars) == 0) {
		const char *v;
		if ((v = evhttp_find_header(&get_vars, "uuid")) != NULL) q_uuid = strdup(v);
		if ((v = evhttp_find_header(&get_vars, "pass")) != NULL) q_pass = strdup(v);
	};
	evhttp_clear_headers(&get_vars);

	if (!q_uuid || !q_pass) {
		DEBUG("Not found user, pass in request from %s", req->remote_host);
		http_err_code = HTTP_BADREQUEST; goto err;
	}

	// Check UUID
	if (5 != sscanf(q_uuid,"%lx-%lx-%lx-%lx-%lx",&uuid[0],&uuid[1],&uuid[2],&uuid[3],&uuid[4])) {
		http_err_code = HTTP_BADREQUEST; goto err;
	}

	// Check SSH session files
	snprintf(record_path, sizeof(record_path), RECORD_UUID_FORMAT,
		opt_records_dir, uuid[0], uuid[1], uuid[2], uuid[3], uuid[4],
		opt_records_suffix);
	if (access(record_path, R_OK) != 0) {
		DEBUG("Can't found file %s", record_path);
		http_err_code = HTTP_NOTFOUND;
		goto err;
	}

	// Prepare proxy session struct
	pp = calloc(1, sizeof(struct proxy_player));
	if (!pp) {
		DEBUG("Can't allocate memory for proxy_player");
		goto err;
	}

	pthread_mutex_init(&pp->mutex, NULL);
	pp->encrypt_pass = q_pass; q_pass = NULL;
	memcpy(&pp->uuid, &uuid, sizeof(uuid));

	// Start thread
	rc = pthread_create(&pp->th, NULL, websocket_proxy_player_thread, (void *)pp);
	if (rc != 0) {
		DEBUG("Unable create pthread");
		goto err;
	}

	rc = pthread_detach(pp->th);
	if (rc != 0) DEBUG("Can't detach pthread");

	// Create WebSocket
	pp->evws = evws_new_session(req, websocket_msg_cb, pp, 0);
	if (!pp->evws) {
		DEBUG("Failed to create websocket session");
		goto err_pthread;
	}

	fd = bufferevent_getfd(evws_connection_get_bufferevent(pp->evws));

	len = sizeof(addr);
	getpeername(fd, (struct sockaddr *)&addr, &len);
	addr2str((struct sockaddr *)&addr, pp->name, sizeof(pp->name));

	evws_connection_set_closecb(pp->evws, websocket_close_cb, pp);

	DEBUG("New client joined from [%s]", pp->name);
	pp->websocket_state = 1; // on

	goto exit;

err_pthread:
	pp->websocket_state = 2; // close

err:
	evhttp_send_error(req, http_err_code, NULL);

exit:
	if (q_uuid) free(q_uuid);
	if (q_pass) free(q_pass);
} // web_play_cb()


static void
web_root_cb(struct evhttp_request *req, void *arg)
{
	struct evbuffer *evb;

	evhttp_add_header(
		evhttp_request_get_output_headers(req), "Content-Type", "text/plain");

	DEBUG("[%s]: %s", req->remote_host, req->uri);

	evb = evbuffer_new();
	if (!evb) goto err;

	evbuffer_add_printf(evb, "Hello %s\n", req->remote_host);
	evbuffer_add_printf(evb, "This is %s records player v%s\n", PROJECT_SUBNAME, PROJECT_VERSION);
	evbuffer_add_printf(evb, "%s/%s\n", PROJECT_GIT, PROJECT_NAME);
	evhttp_send_reply(req, HTTP_OK, NULL, evb);
	evbuffer_free(evb);
	return;

err:
	evhttp_send_error(req, HTTP_NOTFOUND, NULL);
} // web_root_cb()


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
	printf("%s (v%s) proxy records player \n", PROJECT_SUBNAME, PROJECT_VERSION);
	printf("Kuzin Andrey (%s) MIT - %s/%s\n", PROJECT_DATE, PROJECT_GIT, PROJECT_NAME);
	printf("libevent version: \"%s\"\n",event_get_version());
	printf("OpenSSL version: \"%s\"\n",SSLeay_version(SSLEAY_VERSION));
	printf("\nUsage: %s [options]\n", prog);
	printf("\t-f - foreground mode (daemonize by default)\n");
	printf("\t-l <ip> - listening IP (default: \"%s\")\n", opt_server_bind);
	printf("\t-p <port> - listening port (default: %d)\n", opt_server_port);
	printf("\t-k - insecure HTTP mode\n");
	printf("\t-a <fullchain.pem> - fullchain SSL cert PEM file (default: \"%s\")\n",opt_cert_full_chain);
	printf("\t-b <primary> - primary SSL cert PEM file (default: \"%s\")\n",opt_cert_primary);
	printf("\t-d <records_dir> - path to directory with records (default: \"%s\")\n", opt_records_dir);
	printf("\t-s <suffix> - records file suffix (default: \"%s\")\n", opt_records_suffix);
	exit(0);
} // print_help()

int
main(int argc, char **argv)
{
	SSL_CTX *ctx = NULL;

	// Parse program options
	int opt = 0;
	while ( (opt = getopt(argc, argv, "hfl:p:ka:b:d:s:")) != -1)
	switch (opt) {
		case 'h': print_help(argv[0]); break;
		case 'f': opt_foreground = 1; break;
		case 'l': opt_server_bind = optarg; break;
		case 'p': opt_server_port = atoi(optarg); break;
		case 'k': opt_use_ssl = 0; break;
		case 'a': opt_cert_full_chain = optarg; break;
		case 'b': opt_cert_primary = optarg; break;
		case 'd': opt_records_dir = optarg; break;
		case 's': opt_records_suffix = optarg; break;
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
	evhttp_set_cb(http_server, "/play", web_play_cb, NULL);

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
	event_free(sig_term);
	event_base_free(base);

	if (opt_use_ssl) {
		SSL_CTX_free(ctx);
		EVP_cleanup();
	}

	libevent_global_shutdown();

	DEBUG("%s exiting", argv[0]);
	closelog();
	return 0;
}
