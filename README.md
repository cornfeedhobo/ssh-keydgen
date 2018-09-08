ssh-keydgen [![Go Report Card](https://goreportcard.com/badge/github.com/cornfeedhobo/ssh-keydgen)](https://goreportcard.com/report/github.com/cornfeedhobo/ssh-keydgen) [![Build Status](https://travis-ci.org/cornfeedhobo/ssh-keydgen.svg?branch=master)](https://travis-ci.org/cornfeedhobo/ssh-keydgen) [![Github All Releases](https://img.shields.io/github/downloads/cornfeedhobo/ssh-keydgen/total.svg)](https://github.com/cornfeedhobo/ssh-keydgen/releases)
===========

Generate _Deterministic_ SSH keys

```text
NAME:
   ssh-keydgen - deterministic authentication key generation

USAGE:
   ssh-keydgen [[-t <type>] [-b <bits>] [-c <curve>] [-f <filename>] [-a <rounds>] [--at <time>] [--am <memory>] [--as <seedphrase>] [--aa]]

AUTHOR:
   cornfeedhobo

GLOBAL OPTIONS:
   -t type          Specifies the type of key to create. The possible values are "dsa", "ecdsa", "rsa", or "ed25519". (default: "rsa")
   -b bits          Specifies the number of bits in the key to create. Possible values are restricted by key type. (default: 2048)
   -c curve         Specifies the elliptic curve to use. The possible values are 256, 384, or 521. (default: 256)
   -f filename      Specifies the filename of the key file.
   -a rounds        Specifies the number of hashing rounds applied during key generation. (default: 1000)
   --at time        Specifies the time parameter for the Argon2 function. (default: 3)
   --am memory      Specifies the memory parameter for the Argon2 function. (default: 16384)
   --ap threads     Specifies the threads or parallelism for the Argon2 function. (default: 1)
   --as seedphrase  Provides the deterministic seedphrase.
   --aa             Add the generated key to the running ssh-agent.

COPYRIGHT:
   (c) 2018 cornfeedhobo
```



## Usage

1) Generate your keys

   ```bash
   keydgen -f path/to/deterministic_key
   ls -lh path/to/deterministic_key*
   ```

2) Allow time to pass, hoping an emergency does not arise when you have no access to your keys ...

   _If_ the time comes where you need access but can't get to your keys, you can then obtain this
   utility and re-generate, or even directly add your key to a running `ssh-agent`.

   ```bash
   ssh-keydgen --aa
   ```

3) Profit!



## FAQ

### What Go versions are supported?

Go 1.9 or later


### How can I verify the generated key is valid?

Until there are more implementations of this generation scheme, you can
at least verify the private key is usable and the public key matches what
openssh generates.

```bash
cat path/to/deterministic_key.pub
ssh-keygen -y -f path/to/deterministic_key
```

If the above outputs don't match, the public key was not generated properly.
If you are prompted for a password, the private key was not generated properly.


### How can I encrypt my key after generation?

```bash
ssh-keygen -p -f path/to/deterministic_key
```



## Is it any good?

[Yes](http://news.ycombinator.com/item?id=3067434)
