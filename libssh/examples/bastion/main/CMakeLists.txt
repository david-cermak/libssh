idf_component_register(SRCS
        bastion.c
        ssh_vfs.c
    INCLUDE_DIRS .
    REQUIRES esp_netif nvs_flash esp_event
    PRIV_REQUIRES mbedtls lwip
    EMBED_TXTFILES ssh_host_ed25519_key
)
