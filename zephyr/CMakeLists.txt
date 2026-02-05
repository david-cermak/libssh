# SPDX-License-Identifier: Apache-2.0

# Create a Zephyr library
zephyr_library()

set(LIBSSH_VERSION "0.11.0")
set(LIBSSH_DIR "../libssh/libssh-${LIBSSH_VERSION}")
set(LIBSSH_PORT_DIR "../libssh/zephyr")
set(SOCKUTILS_DIR "sock_utils")

set(libssh_SRCS
        agent.c
        auth.c
        base64.c
        bignum.c
        buffer.c
        callbacks.c
        channels.c
        client.c
        config.c
        connect.c
        connector.c
        crypto_common.c
        curve25519.c
        dh.c
        ecdh.c
        error.c
        getpass.c
        init.c
        kdf.c
        kex.c
        known_hosts.c
        knownhosts.c
        #  legacy.c
        log.c
        match.c
        messages.c
        misc.c
        options.c
        packet.c
        packet_cb.c
        packet_crypt.c
        pcap.c
        pki.c
        pki_container_openssh.c
        poll.c
        session.c
        #  scp.c
        socket.c
        string.c
        threads.c
#        ttyopts.c
        wrapper.c
        external/bcrypt_pbkdf.c
        external/blowfish.c
        config_parser.c
        token.c
        pki_ed25519_common.c
)

set(libssh_SRCS
        ${libssh_SRCS}
        threads/mbedtls.c
        libmbedcrypto.c
        mbedcrypto_missing.c
        pki_mbedcrypto.c
        ecdh_mbedcrypto.c
        getrandom_mbedcrypto.c
        md_mbedcrypto.c
        dh_key.c
        pki_ed25519.c
        external/ed25519.c
        external/fe25519.c
        external/ge25519.c
        external/sc25519.c
)

set(libssh_SRCS
        ${libssh_SRCS}
        external/chacha.c
        external/poly1305.c
        chachapoly.c
)

set(libssh_SRCS
        ${libssh_SRCS}
        server.c
        bind.c
        bind_config.c
)

set(libssh_SRCS
        ${libssh_SRCS}
        threads/noop.c
        threads/pthread.c
)

set(libssh_SRCS
        ${libssh_SRCS}
        external/curve25519_ref.c
)


list(TRANSFORM libssh_SRCS PREPEND "${LIBSSH_DIR}/src/")

# Add source files
zephyr_library_sources(
        ${libssh_SRCS}
        ${LIBSSH_PORT_DIR}/zephyr_stubs.c
)

# Make the header file available to other modules
zephyr_library_include_directories(include
                                   ${LIBSSH_DIR}/include
                                   ${LIBSSH_PORT_DIR}
                                   ${SOCKUTILS_DIR}/include
                                    )
