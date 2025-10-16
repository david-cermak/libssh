// Bastion SSH server with simple tunnel command

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "esp_eth.h"
#include "ethernet_init.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

#include "ssh_vfs.h"

static const char* TAG = "bastion_ssh";

#define DEFAULT_PORT "22"
#define DEFAULT_USERNAME "user"
#define DEFAULT_PASSWORD "password"

static volatile int authenticated = 0;
static int tries = 0;
static ssh_channel g_channel = NULL;

// Track simple tunnels by local port
typedef struct tunnel_cfg {
    int listen_port;
    char host[64];
    int host_port;
    struct tunnel_cfg *next;
} tunnel_cfg_t;
static tunnel_cfg_t *s_tunnels = NULL;

// --- Utils ---
static int set_nonblock(int fd, int nb)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    if (nb) flags |= O_NONBLOCK; else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

static int tcp_connect(const char *host, int port)
{
    char portstr[16];
    struct addrinfo hints = {0}, *res = NULL, *p;
    int s = -1;
    snprintf(portstr, sizeof(portstr), "%d", port);
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;
    for (p = res; p; p = p->ai_next) {
        s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (s < 0) continue;
        if (connect(s, p->ai_addr, p->ai_addrlen) == 0) break;
        close(s); s = -1;
    }
    freeaddrinfo(res);
    return s;
}

// --- Forwarding tasks ---
typedef struct {
    int a;
    int b;
} pair_t;

static void bridge_task(void *arg)
{
    pair_t *p = (pair_t*)arg;
    int a = p->a, b = p->b;
    free(p);
    const size_t BUF = 1460;
    uint8_t *buf = malloc(BUF);
    if (!buf) goto out;

    set_nonblock(a, 1); set_nonblock(b, 1);

    while (1) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(a, &rfds); FD_SET(b, &rfds);
        int nfds = (a > b ? a : b) + 1;
        struct timeval tv = { .tv_sec = 30, .tv_usec = 0 };
        int r = select(nfds, &rfds, NULL, NULL, &tv);
        if (r < 0) break;
        if (r == 0) continue;
        if (FD_ISSET(a, &rfds)) {
            int n = recv(a, buf, BUF, 0);
            if (n <= 0) break;
            int off = 0; while (off < n) { int m = send(b, buf + off, n - off, 0); if (m <= 0) { goto out; } off += m; }
        }
        if (FD_ISSET(b, &rfds)) {
            int n = recv(b, buf, BUF, 0);
            if (n <= 0) break;
            int off = 0; while (off < n) { int m = send(a, buf + off, n - off, 0); if (m <= 0) { goto out; } off += m; }
        }
    }
out:
    if (buf) free(buf);
    if (a >= 0) close(a);
    if (b >= 0) close(b);
    vTaskDelete(NULL);
}

typedef struct {
    int listen_port;
    char host[64];
    int host_port;
} listener_cfg_t;

static void listener_task(void *arg)
{
    listener_cfg_t cfg = *(listener_cfg_t*)arg;
    free(arg);
    int ls = -1;
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(cfg.listen_port);

    ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) goto done;
    int one = 1; setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(ls, (struct sockaddr*)&addr, sizeof(addr)) < 0) goto done;
    if (listen(ls, 4) < 0) goto done;
    ESP_LOGI(TAG, "Tunnel listening on :%d -> %s:%d", cfg.listen_port, cfg.host, cfg.host_port);

    while (1) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) continue;
        int rs = tcp_connect(cfg.host, cfg.host_port);
        if (rs < 0) { close(cs); continue; }
        pair_t *pr = malloc(sizeof(pair_t));
        if (!pr) { close(cs); close(rs); continue; }
        pr->a = cs; pr->b = rs;
        xTaskCreate(bridge_task, "tun_fwd", 4096, pr, 9, NULL);
    }

done:
    if (ls >= 0) close(ls);
    vTaskDelete(NULL);
}

static void tunnel_add_and_start(int p1, const char *host, int p2)
{
    // list bookkeeping (optional for now)
    tunnel_cfg_t *node = calloc(1, sizeof(*node));
    if (!node) return;
    node->listen_port = p1; strncpy(node->host, host, sizeof(node->host)-1); node->host_port = p2;
    node->next = s_tunnels; s_tunnels = node;

    listener_cfg_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) return;
    cfg->listen_port = p1; strncpy(cfg->host, host, sizeof(cfg->host)-1); cfg->host_port = p2;
    xTaskCreate(listener_task, "tun_listen", 4096, cfg, 8, NULL);
}


void wifi_init_softap(void);

static void init_ethernet_and_netif(void)
{
    static esp_eth_handle_t *s_eth_handles = NULL;
    static uint8_t s_eth_port_cnt = 0;

    ESP_ERROR_CHECK(ethernet_init_all(&s_eth_handles, &s_eth_port_cnt));

    esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_ETH();
    esp_netif_config_t cfg_spi = {
        .base = &esp_netif_config,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH
    };
    assert(s_eth_port_cnt == 1); // only one Ethernet port supported
        // attach Ethernet driver to TCP/IP stack
    esp_netif_t *eth_netif = esp_netif_new(&cfg_spi);
    assert(eth_netif != NULL);
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(s_eth_handles[0])));
    ESP_ERROR_CHECK(esp_eth_start(s_eth_handles[0]));
}

static void initialize_esp_components(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    // ESP_ERROR_CHECK(example_connect()); // STA or other networking
    init_ethernet_and_netif();
    wifi_init_softap();
}

static int set_hostkey(ssh_bind sshbind)
{
    extern const uint8_t hostkey[] asm("_binary_ssh_host_ed25519_key_start");
    int rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_IMPORT_KEY_STR, hostkey);
    if (rc != SSH_OK) {
        ESP_LOGE(TAG, "Failed to set private key: %s", ssh_get_error(sshbind));
        return SSH_ERROR;
    }
    return SSH_OK;
}

static int auth_none(ssh_session session, const char *user, void *userdata)
{
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    return SSH_AUTH_DENIED;
}

static int auth_password(ssh_session session, const char *user, const char *password, void *userdata)
{
    if (strcmp(user, DEFAULT_USERNAME) == 0 && strcmp(password, DEFAULT_PASSWORD) == 0) {
        authenticated = 1;
        return SSH_AUTH_SUCCESS;
    }
    tries++;
    if (tries >= 3) {
        ssh_disconnect(session);
        return SSH_AUTH_DENIED;
    }
    return SSH_AUTH_DENIED;
}

static int pty_request(ssh_session session, ssh_channel channel, const char *term, int cols, int rows, int py, int px, void *userdata)
{ return SSH_OK; }
static int shell_request(ssh_session session, ssh_channel channel, void *userdata)
{ return SSH_OK; }

static struct ssh_channel_callbacks_struct channel_cb = {
    .userdata = NULL,
    .channel_pty_request_function = pty_request,
    .channel_shell_request_function = shell_request,
};

static ssh_channel on_channel_open(ssh_session session, void *userdata)
{
    if (g_channel) return NULL;
    g_channel = ssh_channel_new(session);
    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(g_channel, &channel_cb);
    return g_channel;
}

// --- VFS glue ---
FILE *backup_out;

static FILE* vfs_init(void)
{
    ssh_vfs_config_t config = {
        .base_path = "/ssh",
        .send_timeout_ms = 10000,
        .recv_timeout_ms = 10000,
        .recv_buffer_size = 256,
        .fallback_stdout = stdout
    };
    ESP_ERROR_CHECK(ssh_vfs_register(&config));
    ssh_vfs_add_client(g_channel, 0);
    FILE *ssh_io = fopen("/ssh/0", "r+");
    if (!ssh_io) return NULL;
    backup_out = _GLOBAL_REENT->_stdout;
    _GLOBAL_REENT->_stdin = ssh_io;
    _GLOBAL_REENT->_stdout = ssh_io;
    _GLOBAL_REENT->_stderr = ssh_io;
    return ssh_io;
}

static void vfs_exit(FILE* ssh_io)
{
    if (ssh_io) fclose(ssh_io);
}

static void vfs_read_task(void* arg)
{
    char buf[1024];
    ssh_channel ch = (ssh_channel)arg;
    while (1) {
        int n = ssh_channel_read(ch, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (buf[0] == '\r') {
            const char nl = '\n';
            ssh_vfs_push_data(ch, &nl, 1);
        } else {
            ssh_vfs_push_data(ch, buf, n);
        }
    }
    vTaskDelete(NULL);
}

static void run_vfs_read_task(ssh_channel ch)
{ xTaskCreate(vfs_read_task, "vfs_read", 4096, ch, 5, NULL); }

// --- Simple REPL ---
static void repl_task(void *arg)
{
    // Basic shell over SSH
    printf("Welcome to ESP32 Bastion\n");
    printf("Commands: help | tun P1:HOST:P2 | tunkill P1 | exit\n\n");
    char line[160];
    while (fgets(line, sizeof(line), stdin)) {
        // trim
        char *e = line + strlen(line); while (e > line && (e[-1]=='\n' || e[-1]=='\r' || e[-1]==' ')) *--e='\0';
        if (strcmp(line, "help") == 0) {
            printf("tun P1:HOST:P2 | tun P1 HOST P2\n");
            printf("tunkill P1\n");
        } else if (strncmp(line, "tun ", 4) == 0) {
            int p1 = 0, p2 = 0; char host[64] = {0};
            const char *args = line + 4;
            if (sscanf(args, "%d:%63[^:]:%d", &p1, host, &p2) == 3) {
                tunnel_add_and_start(p1, host, p2);
                printf("started tunnel :%d -> %s:%d\n", p1, host, p2);
            } else {
                // space separated
                char h2[64]={0}; int n = 0; int x1=0,x2=0;
                n = sscanf(args, "%d %63s %d", &x1, h2, &x2);
                if (n == 3) { tunnel_add_and_start(x1, h2, x2); printf("started tunnel :%d -> %s:%d\n", x1, h2, x2); }
                else { printf("usage: tun <P1>:<HOST>:<P2>\n"); }
            }
        } else if (strncmp(line, "tunkill ", 8) == 0) {
            // Minimal: just note; full implementation would track sockets and close
            int p1 = atoi(line + 8);
            tunnel_cfg_t **pp = &s_tunnels; while (*pp) { if ((*pp)->listen_port == p1) { tunnel_cfg_t *tmp=*pp; *pp=(*pp)->next; free(tmp); break; } pp=&(*pp)->next; }
            printf("request to stop :%d (restart device to fully free listener)\n", p1);
        } else if (strcmp(line, "exit") == 0) {
            break;
        } else if (strcmp(line, "hello") == 0) {
            printf("Hello, world!\n");
        } else if (strcmp(line, "reset") == 0) {
            esp_restart();
        } else if (line[0]) {
            printf("unknown command. type 'help'\n");
        }
        fflush(stdout);
    }
    vTaskDelete(NULL);
}

static void handle_shell(ssh_channel ch)
{
    FILE *io = vfs_init(); if (!io) return;
    run_vfs_read_task(ch);
    xTaskCreate(repl_task, "repl", 2*4096, NULL, 5, NULL);
    while (1) { vTaskDelay(pdMS_TO_TICKS(5000)); }
    vfs_exit(io);
}

static void handle_connection(ssh_session session)
{
    ssh_event event = ssh_event_new();
    if (!event || ssh_event_add_session(event, session) != SSH_OK) return;
    int spins = 0;
    while (authenticated == 0 || g_channel == NULL) {
        if (tries >= 3 || spins >= 100) break;
        if (ssh_event_dopoll(event, 10000) == SSH_ERROR) break;
        spins++;
    }
    if (g_channel) handle_shell(g_channel);
    if (g_channel) { ssh_channel_free(g_channel); g_channel = NULL; }
    ssh_event_free(event);
    ssh_disconnect(session);
    ssh_free(session);
    authenticated = 0; tries = 0;
}

void app_main(void)
{
    initialize_esp_components();
    if (ssh_init() != SSH_OK) return;
    ssh_bind sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, DEFAULT_PORT);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "1");
    if (set_hostkey(sshbind) != SSH_OK || ssh_bind_listen(sshbind) != SSH_OK) {
        ssh_bind_free(sshbind); return;
    }

    ESP_LOGI(TAG, "Bastion SSH listening on 0.0.0.0:%s", DEFAULT_PORT);
    ESP_LOGI(TAG, "Default credentials: %s/%s", DEFAULT_USERNAME, DEFAULT_PASSWORD);

    while (1) {
        ssh_session session = ssh_new();
        if (!session || ssh_bind_accept(sshbind, session) != SSH_OK) { if (session) ssh_free(session); continue; }
        struct ssh_server_callbacks_struct server_cb = {
            .userdata = NULL,
            .auth_none_function = auth_none,
            .auth_password_function = auth_password,
            .channel_open_request_session_function = on_channel_open
        };
        ssh_callbacks_init(&server_cb);
        ssh_set_server_callbacks(session, &server_cb);
        if (ssh_handle_key_exchange(session) == SSH_OK) {
            ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
            handle_connection(session);
        } else { ssh_disconnect(session); ssh_free(session); }
    }
    ssh_bind_free(sshbind);
    ssh_finalize();
}
