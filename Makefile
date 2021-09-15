CGO_ENABLED := 1
GO_LDFLAGS_STATIC=-ldflags "-w -extldflags -static"

ctrwrap: build

rootfs.tar.gz: rootfs.tar
	gzip -f -k rootfs.tar

rootfs.tar:
	docker export $(shell docker create quay.io/sysdig/secure-inline-scan:2) -o rootfs.tar
	mkdir rootfs
	tar -C rootfs -xvf rootfs.tar
	chmod -R u+rw rootfs/*
	rm rootfs.tar
	tar -C rootfs -cvf rootfs.tar .
	rm -f -r rootfs

build-static: rootfs.tar.gz main.go
	docker run --rm -v $(shell pwd):/go/src/app -w /go/src/app golang:1.17-stretch go build ${GO_LDFLAGS_STATIC} -o ctrwrap main.go

build: rootfs.tar.gz main.go
	docker run --rm -v $(shell pwd):/go/src/app -w /go/src/app golang:1.17-stretch go build -o ctrwrap main.go
#	docker run --rm -v $(shell pwd):/go/src/app -w /go/src/app golang:1.17-stretch sh -c "objdump -T ctrwrap | grep GLIBC_"

build-local: main.go
	CGO_ENABLED=$(CGO_ENABLED)  go build ${GO_LDFLAGS_STATIC} -o ctrwrap main.go
