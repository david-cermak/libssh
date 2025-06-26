/*
 * Simple SSH Server Example
 *
 * This is a minimal SSH server that:
 * - Listens on 0.0.0.0 (all interfaces)
 * - Accepts password authentication
 * - Provides a simple shell
 * - Uses the built libssh library
 */

#include <stdio.h>
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "mqtt_client.h"
#include "esp_log.h"
#include "protocol_examples_common.h"
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

#define DEFAULT_PORT "2222"
#define DEFAULT_USERNAME "DAVID"
#define DEFAULT_PASSWORD "password"

static int authenticated = 0;
static int tries = 0;
static ssh_channel channel = NULL;

// Forward declarations
static int pty_request(ssh_session session, ssh_channel channel,
                      const char *term, int cols, int rows,
                      int py, int px, void *userdata);
static int shell_request(ssh_session session, ssh_channel channel, void *userdata);

// Authentication callback - deny none authentication
static int auth_none(ssh_session session, const char *user, void *userdata) {
    (void)user;
    (void)userdata;

    printf("[DEBUG] Auth none requested for user: %s\n", user);
    ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
    return SSH_AUTH_DENIED;
}

// Password authentication callback
static int auth_password(ssh_session session, const char *user,
                        const char *password, void *userdata) {
    (void)userdata;

    printf("[DEBUG] Password auth attempt for user: %s\n", user);

    if (strcmp(user, DEFAULT_USERNAME) == 0 &&
        strcmp(password, DEFAULT_PASSWORD) == 0) {
        authenticated = 1;
        printf("[DEBUG] Authentication successful for user: %s\n", user);
        return SSH_AUTH_SUCCESS;
    }

    tries++;
    if (tries >= 3) {
        printf("[DEBUG] Too many authentication attempts\n");
        ssh_disconnect(session);
        return SSH_AUTH_DENIED;
    }

    printf("[DEBUG] Authentication failed (attempt %d/3)\n", tries);
    return SSH_AUTH_DENIED;
}

    struct ssh_channel_callbacks_struct channel_cb = {
        .userdata = NULL,
        .channel_pty_request_function = pty_request,
        .channel_shell_request_function = shell_request,
        // .channel_data_function = data_function
    };


// Channel open callback
static ssh_channel channel_open(ssh_session session, void *userdata) {
    (void)userdata;

    if (channel != NULL) {
        printf("[DEBUG] Channel already exists\n");
        return NULL;
    }

    printf("[DEBUG] Opening new channel\n");
    channel = ssh_channel_new(session);

    // Set up channel callbacks

    ssh_callbacks_init(&channel_cb);
    ssh_set_channel_callbacks(channel, &channel_cb);

    printf("[DEBUG] Channel created and callbacks set\n");
    return channel;
}

// PTY request callback
static int pty_request(ssh_session session, ssh_channel channel,
                      const char *term, int cols, int rows,
                      int py, int px, void *userdata) {
    (void)session;
    (void)channel;
    (void)term;
    (void)cols;
    (void)rows;
    (void)py;
    (void)px;
    (void)userdata;

    printf("[DEBUG] PTY requested: %s (%dx%d)\n", term, cols, rows);
    return SSH_OK;
}

// Shell request callback
static int shell_request(ssh_session session, ssh_channel channel, void *userdata) {
    (void)session;
    (void)userdata;

    printf("[DEBUG] Shell requested\n");

    if (channel == NULL) {
        printf("[DEBUG] Shell requested but channel is NULL\n");
        return SSH_ERROR;
    }

    // // Send a welcome message
    // int rc = ssh_channel_write(channel, "Welcome to Simple SSH Server!\n", 30);
    // if (rc != SSH_OK) {
    //     printf("[DEBUG] Failed to write welcome message: %s\n", ssh_get_error(session));
    //     return SSH_ERROR;
    // }

    // rc = ssh_channel_write(channel, "Type 'exit' to disconnect.\n\n", 26);
    // if (rc != SSH_OK) {
    //     printf("[DEBUG] Failed to write exit message: %s\n", ssh_get_error(session));
    //     return SSH_ERROR;
    // }

    // // Send initial prompt
    // rc = ssh_channel_write(channel, "$ ", 2);
    // if (rc != SSH_OK) {
    //     printf("[DEBUG] Failed to write prompt: %s\n", ssh_get_error(session));
    //     return SSH_ERROR;
    // }

    printf("[DEBUG] Shell setup completed successfully\n");
    return SSH_OK;
}

// Data callback for handling incoming data
// static int data_function(ssh_session session, ssh_channel channel,
//                         void *data, uint32_t len, int is_stderr, void *userdata) {
//     (void)session;
//     (void)channel;
//     (void)data;
//     (void)is_stderr;
//     (void)userdata;

//     printf("[DEBUG] Received %u bytes of data\n", (int)len);

//     if (channel == NULL || data == NULL) {
//         printf("[DEBUG] Data function called with NULL channel or data\n");
//         return SSH_ERROR;
//     }

//     // Echo back what was received
//     int rc = ssh_channel_write(channel, "Received: ", 10);
//     if (rc != SSH_OK) {
//         printf("[DEBUG] Failed to write 'Received:' prefix\n");
//         return SSH_ERROR;
//     }

//     rc = ssh_channel_write(channel, data, len);
//     if (rc != SSH_OK) {
//         printf("[DEBUG] Failed to echo data back\n");
//         return SSH_ERROR;
//     }

//     // Send new prompt
//     rc = ssh_channel_write(channel, "\n$ ", 3);
//     if (rc != SSH_OK) {
//         printf("[DEBUG] Failed to write prompt\n");
//         return SSH_ERROR;
//     }

//     return SSH_OK;
// }

static int load_hardcoded_key(ssh_bind sshbind)
{
    int rc;
    static char opensshkey[] = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                            "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n"
                            "NhAAAAAwEAAQAAAQEAt2tSRVSleWZNIJ3sAkrlov0sz55cZ8IPjd8jDcIVN8r5ppOclWcL\n"
                            "GebRbJnQH2A7fRwluNPckDZH4WtObJu7uVliB8gHmreqYzjSYgeWtbch71r1CQ7QG+RqgL\n"
                            "RBZXglRtm6GaAheRQg5E1RRrVjSh29U7GRe80zq3deVgmXb70w7XU3IhmIBgh6BcHUe+Lf\n"
                            "bBUW/kiHnfYPZGvITZHOYSR2q/NP2BjCnV2gSsdKDVWQ27DvEfcB8xcEtg28l203Q/ZmvP\n"
                            "oGuWvfcv1siVH7kb8IK+DYpejXnE5f85k9z/2i/HxJM3NnfIlKHgfPKTDBZLr463tT+xD4\n"
                            "Fr+o3BGgoQAAA8hNX/+VTV//lQAAAAdzc2gtcnNhAAABAQC3a1JFVKV5Zk0gnewCSuWi/S\n"
                            "zPnlxnwg+N3yMNwhU3yvmmk5yVZwsZ5tFsmdAfYDt9HCW409yQNkfha05sm7u5WWIHyAea\n"
                            "t6pjONJiB5a1tyHvWvUJDtAb5GqAtEFleCVG2boZoCF5FCDkTVFGtWNKHb1TsZF7zTOrd1\n"
                            "5WCZdvvTDtdTciGYgGCHoFwdR74t9sFRb+SIed9g9ka8hNkc5hJHar80/YGMKdXaBKx0oN\n"
                            "VZDbsO8R9wHzFwS2DbyXbTdD9ma8+ga5a99y/WyJUfuRvwgr4Nil6NecTl/zmT3P/aL8fE\n"
                            "kzc2d8iUoeB88pMMFkuvjre1P7EPgWv6jcEaChAAAAAwEAAQAAAQAbhzP1y9p5+eyhdJIz\n"
                            "VeJZL/5FutLLj8id1luAeRyOHxyQ756Unb6AyK+tyPf/fYXwJQVUVBfKXRs0rdI7YrQuAU\n"
                            "hBOrhJdD9SXPjWVaU86JtjPReBoIODbCi/4E3gWMPfelX/+pSLg4XcPe5w2lBok0YTBZd8\n"
                            "KTQUC/pQl2fvEQjd3AN3PB4zZBEGCn7uEhu7GJACfSx3jfJgDU+9Z7vP2nL8Vj35M2wqtC\n"
                            "2QVyDgw/VvtCHshH9GqYTCNaqQTUr78edwH4f3DTik1PCJ7KsmrtHBAoi4eC6lz5mU9rz3\n"
                            "OQSt/IyseCcZZebPnHC3KuAwsQZcllnz48mCLi5lhSCxAAAAgQCG30hqEGkC/DXJCIpkla\n"
                            "44bpyFi76U1zgqpQJ7zMpgBeLglAUsT2V4nlMxS/QPZGH2Glng1oc3eMz6gHvHlYqC/Dfj\n"
                            "R5wBmd63ZoHnBvCuNHT1OKUN5fCS5yipIFo7JYywSSuqrsZpw2w9ppLtPHfcdg+hD5UoQI\n"
                            "h2eZ8eQbUx7wAAAIEA5QrGTr6+xnH9ZuwM6J+2QD6W/RWBjuTsighbErm05nb8SKrlbglz\n"
                            "X5WuaSYh5tr5PBVeqmcomzmKBUGui4Anz7704lBiTUcoH6zyZTkHI1koJ93tmQLgfRqqPD\n"
                            "A40Iqc1O3bM1IBX63mg53Mb+6UHNALWTtM4oH320LS/DpxYv8AAACBAM0B5H0SrqEcDXVS\n"
                            "qnw+AhleT7FOWu9wNAz1obx7aVCoTWBRz0DfKav0NRcrL9GNpBug5+6oWUkuIV2txqeDi+\n"
                            "dUx/ZDzzYZiMe8hzFnD3m1XOCEZA5Q3lEwYQGZ7wDyxPVvhW2DNO5CsIMapIMNVfiAqnFs\n"
                            "LkXl2FJJrZH81hxfAAAAEGRhdmlkQGRhdmlkLXdvcmsBAg==\n"
                            "-----END OPENSSH PRIVATE KEY-----\n";

    // Set the hardcoded private key directly
    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_IMPORT_KEY_STR, opensshkey);
    if (rc != SSH_OK) {
        fprintf(stderr, "Failed to set hardcoded private key: %s\n", ssh_get_error(sshbind));
        return SSH_ERROR;
    }

    printf("[DEBUG] Successfully loaded hardcoded private key\n");
    return SSH_OK;
}

void app_main(void)
{
    ssh_bind sshbind;
    ssh_session session;
    ssh_event event;
    int rc;
    const char *port = DEFAULT_PORT;

    // Initialize ESP-IDF components
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(example_connect());

    // Initialize libssh
    rc = ssh_init();
    if (rc != SSH_OK) {
        fprintf(stderr, "Failed to initialize libssh: %d\n", rc);
        return;
    }

    // Create SSH bind object
    sshbind = ssh_bind_new();
    if (sshbind == NULL) {
        fprintf(stderr, "Failed to create SSH bind object\n");
        return;
    }

    // Set bind options
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_LOG_VERBOSITY_STR, "1");

    // Set host key (hardcoded for now)
    load_hardcoded_key(sshbind);

    // Listen for connections
    rc = ssh_bind_listen(sshbind);
    if (rc != SSH_OK) {
        fprintf(stderr, "Failed to listen on 0.0.0.0:%s: %s\n",
                port, ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        return;
    }

    printf("Simple SSH Server listening on 0.0.0.0:%s\n", port);
    printf("Default credentials: %s/%s\n", DEFAULT_USERNAME, DEFAULT_PASSWORD);

    // Accept connections
    while (1) {
        session = ssh_new();
        if (session == NULL) {
            fprintf(stderr, "Failed to create session\n");
            continue;
        }

        rc = ssh_bind_accept(sshbind, session);
        if (rc != SSH_OK) {
            fprintf(stderr, "Failed to accept connection: %s\n",
                    ssh_get_error(sshbind));
            ssh_free(session);
            continue;
        }

        printf("[DEBUG] New connection accepted\n");

        // Set up server callbacks
        struct ssh_server_callbacks_struct server_cb = {
            .userdata = NULL,
            .auth_none_function = auth_none,
            .auth_password_function = auth_password,
            .channel_open_request_session_function = channel_open
        };

        ssh_callbacks_init(&server_cb);
        ssh_set_server_callbacks(session, &server_cb);
        printf("[DEBUG] Server callbacks set\n");

        // Handle key exchange
        rc = ssh_handle_key_exchange(session);
        if (rc != SSH_OK) {
            fprintf(stderr, "[DEBUG] Key exchange failed: %s\n",
                    ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        printf("[DEBUG] Key exchange completed\n");

        // Set up authentication methods
        ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
        printf("[DEBUG] Authentication methods set\n");

        // Create event for session handling
        event = ssh_event_new();
        if (event == NULL) {
            fprintf(stderr, "[DEBUG] Failed to create event\n");
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        // Add session to event
        if (ssh_event_add_session(event, session) != SSH_OK) {
            fprintf(stderr, "[DEBUG] Failed to add session to event\n");
            ssh_event_free(event);
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        printf("[DEBUG] Session added to event, starting main loop\n");

        // Check initial channel state
        printf("[DEBUG] Initial channel state: channel=%p, is_open=%s\n",
               channel, channel ? (ssh_channel_is_open(channel) ? "yes" : "no") : "NULL");

        // Wait for authentication and channel creation (like the official example)
        int n = 0;
        while (authenticated == 0 || channel == NULL) {
            printf("[DEBUG] Waiting for auth/channel: auth=%s, channel=%p (attempt %d)\n",
                   authenticated ? "yes" : "no", channel, n);

            // If the user has used up all attempts, or if he hasn't been able to
            // authenticate in 10 seconds (n * 100ms), disconnect.
            if (tries >= 3 || n >= 100) {
                printf("[DEBUG] Timeout waiting for authentication/channel\n");
                break;
            }

            if (ssh_event_dopoll(event, 1000) == SSH_ERROR) {
                printf("[DEBUG] Error polling events: %s\n", ssh_get_error(session));
                break;
            }
            n++;
        }

        // If we have a channel, set up callbacks and continue
        if (channel != NULL) {
            printf("[DEBUG] Channel created, setting up callbacks\n");
            #define BUF_SIZE 2049
            char buf[BUF_SIZE];
            int i;
            int count = 0;
            char command[100];

            printf("[DEBUG] Channel created, setting up callbacks\n");

            // Set up channel callbacks
            // struct ssh_channel_callbacks_struct channel_cb = {
            //     .userdata = NULL,
            //     .channel_pty_request_function = pty_request,
            //     .channel_shell_request_function = shell_request,
            //     .channel_data_function = data_function
            // };

            // ssh_callbacks_init(&channel_cb);
            // ssh_set_channel_callbacks(channel, &channel_cb);
            do{
                i=ssh_channel_read(channel, buf, sizeof(buf) - 1, 0);
                if (i>0) {
                    if (ssh_channel_write(channel, buf, i) == SSH_ERROR) {
                        printf("error writing to channel\n");
                        return;
                    }

                    buf[i] = '\0';
                    printf("%s", buf);
                    fflush(stdout);
                    if (count < 100) {
                        memcpy(command + count, buf, i);
                        count += i;
                    }

                    if (buf[0] == '\x0d') {
                        printf("[INFO] Command: %s", command);
                        if (memcmp(command, "exit", 4) == 0) {
                            printf("[DEBUG] Exit command received\n");
                            break;
                        }
                        if (memcmp(command, "reset", 5) == 0) {
                            printf("[DEBUG] Reset command received\n");
                            esp_restart();
                            // break;
                        }
                        if (memcmp(command, "hello", 5) == 0) {
                            printf("[DEBUG] Hello command received\n");
                            if (ssh_channel_write(channel, "Hello, world!\n", 14) == SSH_ERROR) {
                                printf("error writing to channel\n");
                                return;
                            }
                        }


                        count = 0;
                        if (ssh_channel_write(channel, "\n", 1) == SSH_ERROR) {
                            printf("error writing to channel\n");
                            return;
                        }

                        printf("\n");
                    }
                }
            } while (i>0);

            // Set up channel callbacks
            // struct ssh_channel_callbacks_struct channel_cb = {
            //     .userdata = NULL,
            //     .channel_pty_request_function = pty_request,
            //     .channel_shell_request_function = shell_request,
            //     .channel_data_function = data_function
            // };

            // ssh_callbacks_init(&channel_cb);
            // ssh_set_channel_callbacks(channel, &channel_cb);

            // Continue polling until channel closes
            // while (ssh_channel_is_open(channel)) {
            //     if (ssh_event_dopoll(event, 1000) == SSH_ERROR) {
            //         printf("[DEBUG] Error polling events: %s\n", ssh_get_error(session));
            //         break;
            //     }
            // }
        }

        printf("[DEBUG] Connection closed\n");

        // Clean up
        if (channel != NULL) {
            ssh_channel_free(channel);
            channel = NULL;
        }
        authenticated = 0;
        tries = 0;
        ssh_event_free(event);
        ssh_disconnect(session);
        ssh_free(session);
    }

    // Clean up
    ssh_bind_free(sshbind);
    ssh_finalize();

}



#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>

/* Dummy getuid() */
uid_t getuid(void)
{
    return 0;  // Return fake UID
}

/* Dummy getpwuid_r */
int getpwuid_r(uid_t uid, struct passwd *pwd, char *buf, size_t buflen, struct passwd **result)
{
    if (result) {
        *result = NULL;
    }
    return -1;  // Simulate failure
}

/* Dummy getpwnam */
struct passwd *getpwnam(const char *name)
{
    return NULL;
}

/* Dummy waitpid */
pid_t waitpid(pid_t pid, int *wstatus, int options)
{
    return -1;  // Simulate failure
}
