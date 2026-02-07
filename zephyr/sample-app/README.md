## libssh Zephyr sample app (SSH server)

This is a minimal Zephyr demo application that uses the libssh module to run
an SSH server after joining Wi-Fi. It is intentionally small and uses the
existing `src/wifi.c` and `src/server.c` sources from this repository.

### Project layout

Create a new Zephyr application folder with this minimal layout:

```
sample-app/
  CMakeLists.txt
  prj.conf
  mbedtls_user_config.h
  src/
    wifi.c
    server.c
```

### Optional `west.yml`

If you want a standalone manifest, add a minimal `west.yml` that pulls Zephyr
and the libssh module:

```
manifest:
  projects:
    - name: zephyr
      url: https://github.com/zephyrproject-rtos/zephyr
      revision: main
      import: true
    - name: libssh
      url: https://github.com/david-cermak/libssh/zephyr
      revision: TBD
  self:
    path: app
```

Otherwise, you can keep the libssh module locally and point
`EXTRA_ZEPHYR_MODULES` at it in your `CMakeLists.txt`.

### CMakeLists.txt (minimal)

```
cmake_minimum_required(VERSION 3.20.0)

set(EXTRA_ZEPHYR_MODULES /path/to/libssh)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ssh_server_demo)

target_sources(app PRIVATE src/wifi.c src/server.c)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/modules2/libssh/libssh/libssh-0.11.0/include
  ${CMAKE_CURRENT_SOURCE_DIR}/modules2/libssh/libssh/zephyr
)
```

### prj.conf (minimal)

Start with the basics needed for Wi-Fi, networking, sockets, and mbedTLS:

```
CONFIG_WIFI=y
CONFIG_NET_L2_WIFI_MGMT=y
CONFIG_NETWORKING=y
CONFIG_NET_IPV4=y
CONFIG_NET_TCP=y
CONFIG_NET_SOCKETS=y
CONFIG_NET_DHCPV4=y
CONFIG_POSIX_API=y

CONFIG_MAIN_STACK_SIZE=8192
CONFIG_SYSTEM_WORKQUEUE_STACK_SIZE=8192

CONFIG_MBEDTLS_CIPHER=y
CONFIG_MBEDTLS_SHA256=y
CONFIG_MBEDTLS_ECP_C=y
CONFIG_MBEDTLS_ECDSA_C=y
CONFIG_MBEDTLS_RSA_C=y
CONFIG_MBEDTLS_MD_C=y

CONFIG_MBEDTLS_USER_CONFIG_ENABLE=y
CONFIG_MBEDTLS_USER_CONFIG_FILE="mbedtls_user_config.h"
```

### mbedtls_user_config.h (minimal)

```
#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H

#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_ERROR_C
#define MBEDTLS_THREADING_PTHREAD
#define MBEDTLS_THREADING_C

#endif /* MBEDTLS_USER_CONFIG_H */
```

### src/wifi.c (fragment)

This app uses a simple Wi-Fi bring-up then calls the SSH server entry point:

```
#define SSID "your-ssid"
#define PSK "your-psk"

int main(void)
{
    printk("SSH Server example\nBoard: %s\n", CONFIG_BOARD);

    wifi_connect();
    k_sem_take(&wifi_connected, K_FOREVER);
    wifi_status();
    k_sem_take(&ipv4_address_obtained, K_FOREVER);

    app_main();
    return 0;
}
```

### src/server.c (fragment)

The SSH server listens on all interfaces and uses libssh callbacks:

```
#define DEFAULT_PORT "2222"
#define DEFAULT_USERNAME "david"
#define DEFAULT_PASSWORD "password"

void app_main(void)
{
    ssh_bind sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, DEFAULT_PORT);
    ssh_bind_listen(sshbind);

    while (1) {
        ssh_session session = ssh_new();
        ssh_bind_accept(sshbind, session);
        ssh_handle_key_exchange(session);
        /* ... auth + channel handling ... */
    }
}
```

### Build

```
west build -b <your_board> sample-app
```

Replace SSID/PSK and credentials, then flash as usual for your board.
