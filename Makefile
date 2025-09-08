all: builds/gomonitor.linux.amd64 builds/gomonitor.linux.arm64

clean:
	rm -f builds/*

builds/gomonitor.linux.amd64: gomonitor.go goalarmeitbl/*.go
	( GOOS=linux GOARCH=amd64 go build -o $@ gomonitor.go )

builds/gomonitor.linux.arm64: gomonitor.go goalarmeitbl/*.go
	( GOOS=linux GOARCH=arm64 go build -o $@ gomonitor.go )
