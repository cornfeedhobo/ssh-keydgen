ssh-keydgen [![Travis](https://img.shields.io/travis/cornfeedhobo/ssh-keydgen.svg)]() [![Github All Releases](https://img.shields.io/github/downloads/cornfeedhobo/ssh-keydgen/total.svg)]()
===========

 Generate _Deterministic_ SSH keys
 
   ```text
   NAME:
      ssh-keydgen - Deterministic authentication key generation
   
   USAGE:
      ssh-keydgen [-t] [-b] [-c] [-n] [-f] [-a]
   
   AUTHOR:
      cornfeedhobo
   
   OPTIONS:
      -t type      Specifies the type of key to create. The possible values are "dsa", "ecdsa", "rsa", or "ed25519". (default: "ed25519")
      -b bits      Specifies the number of bits in the key to create. Possible values are restricted by key type. (default: 2048)
      -c curve     Specifies the elliptic curve to use. The possible values are 256, 384, or 521. (default: 256)
      -n factor    Specifies the work factor, or "difficulty", applied to the key generation function. (default: 16384)
      -f filename  Specifies the filename of the key file.
      -a           Add the generated key to the running ssh-agent.

   COPYRIGHT:
      (c) 2017 cornfeedhobo
   ```



## Usage

 1) Generate your keys
    ```bash
    keydgen -f deterministic_key
    ls -lh deterministic_key*
    ```
    
 2) Allow time to pass, hoping an emergency does not arise when you have no access to your keys ...
    
    _If_ the time comes where you need access but can't get to your keys, you can then obtain this
    utility and re-generate, or even directly add your key to a running `ssh-agent`.
    ```bash
    keydgen -a
    ```
    
 3) Profit!



## Is it any good?

 [Yes](http://news.ycombinator.com/item?id=3067434)
