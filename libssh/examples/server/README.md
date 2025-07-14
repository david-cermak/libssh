# Simple SSH server

## How to use this example

### Generate SSH Host Keys

This example uses a hardcoded SSH host key for demonstration purposes, the demo host public key is also added for reference (to the `main` folder, it's fingerprint is `256 SHA256:XHZN4rhQ8EU4QeWCfG2+jNS7ONoKCw5DUkpiyKFFRpY`).

In a real project, you should generate your own unique host key using the `ssh-keygen` command.

**Recommended: Ed25519 Keys (Best Security & Performance)**

Ed25519 is the most secure and performant key type currently available:

```bash
ssh-keygen -t ed25519 -f ssh_host_ed25519_key -N ""
```

Alternatively use RSA or ECDSA Keys

```bash
ssh-keygen -t rsa -b 4096 -f ssh_host_rsa_key -N ""
ssh-keygen -t ecdsa -b 521 -f ssh_host_ecdsa_key -N ""
```

Copy the key to `main/ssh_host_ed25519_key` and rebuild the project

The server will automatically use your key for all SSH connections on port 2222 (default).

### Configure and build

* Configure the connection (WiFi or Ethernet per your board options)
* Build and run the project normally with `idf.py build flash monitor`

### Connect to the server

```
ssh user@[IP-address] -p 2222
```
and use the default user/password to login

run some demo commands provided by this example
* `reset` -- restarts the ESP32
* `hello` -- says hello-world
* `exit` -- exit the shell
