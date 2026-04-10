set(LIBSSH_VERSION "0.12.0")
set(LIBSSH_DIR "libssh-${LIBSSH_VERSION}")

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
  mlkem.c
  options.c
  packet.c
  packet_cb.c
  packet_crypt.c
  pcap.c
  pki.c
  pki_context.c
  pki_container_openssh.c
  poll.c
  session.c
#  scp.c
  socket.c
  string.c
  threads.c
  ttyopts.c
  wrapper.c
  gzip.c
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
    hybrid_mlkem.c
    sntrup761.c
    external/ed25519.c
    external/fe25519.c
    external/ge25519.c
    external/sc25519.c
    external/sntrup761.c
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
    curve25519_fallback.c
    external/curve25519_ref.c
)

set(libssh_SRCS
${libssh_SRCS}
    mlkem_native.c
    external/libcrux_mlkem768_sha3.c
)

list(TRANSFORM libssh_SRCS PREPEND "${LIBSSH_DIR}/src/")

idf_component_register(SRCS ${libssh_SRCS}
                            port/idf_stubs.c
                    INCLUDE_DIRS ${LIBSSH_DIR}/include port
                    PRIV_REQUIRES esp_netif mbedtls)

target_compile_definitions(${COMPONENT_LIB} PRIVATE LIBSSH_STATIC)
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-int-conversion")
target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-char-subscripts")

if("${IDF_VERSION_MAJOR}.${IDF_VERSION_MINOR}" VERSION_GREATER_EQUAL "6.0")
# pre-include mbedtls_v3_shim to provide compatibility for mbedtls v3 API used by libssh
idf_component_get_property(mbedtls_v3_shim_dir david-cermak__mbedtls_v3_shim COMPONENT_DIR)
target_include_directories(${COMPONENT_LIB} BEFORE PRIVATE
    "${mbedtls_v3_shim_dir}/include")
endif()

set_source_files_properties(${LIBSSH_DIR}/src/external/bcrypt_pbkdf.c PROPERTIES COMPILE_OPTIONS "-Wno-unterminated-string-initialization")
set_source_files_properties(${LIBSSH_DIR}/src/external/chacha.c PROPERTIES COMPILE_OPTIONS "-Wno-unterminated-string-initialization")
set_source_files_properties(${LIBSSH_DIR}/src/external/libcrux_mlkem768_sha3.c PROPERTIES COMPILE_OPTIONS "-Wno-declaration-after-statement")
