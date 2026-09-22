all: builds/vmonitor.linux.amd64 builds/vmonitor.linux.arm64 vmonitor

clean:
	rm -f builds/*

builds/vmonitor.linux.amd64: vmonitor.go goalarmeitbl/*.go
	( GOOS=linux GOARCH=amd64 go build -o $@ vmonitor.go )

builds/vmonitor.linux.arm64: vmonitor.go goalarmeitbl/*.go
	( GOOS=linux GOARCH=arm64 go build -o $@ vmonitor.go )

vmonitor: vmonitor.go goalarmeitbl/*.go
	go build -o vmonitor vmonitor.go
