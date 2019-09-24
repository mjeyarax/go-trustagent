GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)

gta:
	env GOOS=linux go build -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/version.Version=$(VERSION) -X intel/isecl/go-trust-agent/version.GitHash=$(GITCOMMIT)" -o out/tagent

# KWT
# Pass the '-w' flag to the linker to omit the debug information (for example, go build -ldflags=-w prog.go).
# https://golang.org/doc/gdb

installer: gta
	mkdir -p out/installer
	cp dist/linux/tagent.service out/installer/tagent.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/module_analysis.sh out/installer/module_analysis.sh && chmod +x out/installer/module_analysis.sh
	cp dist/linux/module_analysis_da.sh out/installer/module_analysis_da.sh && chmod +x out/installer/module_analysis_da.sh
	cp dist/linux/module_analysis_da_tcg.sh out/installer/module_analysis_da_tcg.sh && chmod +x out/installer/module_analysis_da_tcg.sh
	
	cp out/tagent out/installer/tagent
	makeself out/installer out/trustagent-$(VERSION).bin "TrustAgent $(VERSION)" ./install.sh

all: gta

clean:
	rm -f cover.*
	rm -rf out/
	rm -rf builds/