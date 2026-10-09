PLATFORMS = linux.amd64 linux.arm64

BINARIES = $(foreach p,$(PLATFORMS),builds/vmonitor.$(p))
SOURCES = vmonitor.go $(wildcard goalarmeitbl/*.go) go.mod go.sum

all: $(BINARIES) vmonitor

clean:
	rm -f builds/* vmonitor

test:
	go vet ./...

e2e:
	./e2e_test.py

# builds/vmonitor.<os>.<arch>
builds/vmonitor.%: $(SOURCES)
	GOOS=$(word 1,$(subst ., ,$*)) GOARCH=$(word 2,$(subst ., ,$*)) \
		go build -trimpath -o $@ .

vmonitor: $(SOURCES)
	go build -o vmonitor .

.PHONY: all clean test e2e
