CGO_ENABLED := 1
GO_LDFLAGS_STATIC=-ldflags "-w -extldflags -static"

ctrwrap: build

build: main.go
	CGO_ENABLED=$(CGO_ENABLED)  go build ${GO_LDFLAGS_STATIC} -o ctrwrap main.go
