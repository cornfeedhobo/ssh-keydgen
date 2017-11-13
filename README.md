ssh-keydgen [![Travis](https://img.shields.io/travis/cornfeedhobo/ssh-keydgen.svg)]() [![Github All Releases](https://img.shields.io/github/downloads/cornfeedhobo/ssh-keydgen/total.svg)]()
===========

Generate _Deterministic_ SSH keys

## Usage
   ```text
   NAME:
      ssh-keydgen - deterministic authentication key generation
   
   USAGE:
      ssh-keydgen [-t] [-b] [-c] [-o] [-a]
   
   AUTHOR:
      cornfeedhobo
   
   OPTIONS:
      -t type   Specifies the type of key to create. The possible values are “dsa”, “ecdsa”, “ed25519”, or “rsa”. (default: "ed25519")
      -b bits   Specifies the number of bits in the key to create. Possible values are restricted by key type. (default: 2048)
      -c curve  Specifies the elliptic curve to use. The possible values are 256, 384, or 521. (default: 256)
      -o path   Specifies the path to output the generated key.
      -a        Add the generated key to the running ssh-agent.

   COPYRIGHT:
      (c) 2017 cornfeedhobo
   ```



## Is it any good?

[Yes](http://news.ycombinator.com/item?id=3067434)
