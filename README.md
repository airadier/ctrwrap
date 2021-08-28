# ctrwap

Experimental: wrap the Sysdig inline-scanner in a self-contained container using runc and embedding the rootfs

## How to build

Put rootfs.tar.gz and config.json in current folder and:

```
make
```

Root filesytem can be created with:
```
docker export (docker create secure-inline-scan:2) -o rootfs.tar
```
and then compressed with gzip

To generate the config.json:
 * Create a container with `ctr c create quay.io/sysdig/secure-inline-scan:2 foo`
 * Get the spec with `ctr c info foo --spec > config.json`

Caveats:
* Requires running as root (although rootless should be possible)
* All files in the .tar.gz must have "w" permission for the user or extract fails. So (as in this case) you might need to extract the root filesystem, then `chmod -R u+rw *` and re-tar again. 
