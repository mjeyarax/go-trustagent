GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)

gta:
	env GOOS=linux go build -ldflags "-X intel/isecl/go-trust-agent/version.Version=$(VERSION) -X intel/isecl/go-trust-agent/version.GitHash=$(GITCOMMIT)" -o out/tagent

all: gta

clean:
	rm -f cover.*
	rm -rf out/
	rm -rf builds/