Libsodium password hashing schemes plugin
=========================================

> ⚠️ **Compatibility**
>
> Compatible with Dovecot < 2.3.0 only

Requires installed libsodium: https://download.libsodium.org/doc/installation/


**Configure, Compile, Install the plugin:**  
./autogen.sh  
./configure  
make  
sudo make install  
  
  
**Test the plugin:**
doveadm pw -s scrypt  
doveadm pw -s argon2  
  
---
> ❌ **Obsolete**
>
> This plugin became obsolete with the release of **Dovecot 2.3.0**, which introduced native support for modern password hashing algorithms such as **Argon2**.
> 
> 👉 See [Issue #5](https://github.com/LuckyFellow/dovecot-libsodium-plugin/issues/5) for details.<br>
> Previously used in production to provide `scrypt` and early `argon2` support via `libsodium`, before official integration.<br>
> Bridged the gap until native support for modern password hashing became available.
