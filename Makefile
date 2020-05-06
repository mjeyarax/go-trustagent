GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)
VERSION := $(or ${GITTAG}, v1.0.0)

# TODO:  Update make file to support debug/release builds (release build to use secure gcflags)
# -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIE -fPIC -fstack-protector-strong -O2 -D
gta:
	export CGO_CFLAGS_ALLOW="-f.*"; \
	env GOOS=linux GOSUMDB=off GOPROXY=direct go build -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/v2/util.Version=$(VERSION) -X intel/isecl/go-trust-agent/v2/util.GitHash=$(GITCOMMIT) -X intel/isecl/go-trust-agent/v2/util.BuildDate=$(BUILDDATE)" -o out/tagent

installer: gta
	mkdir -p out/installer
	cp dist/linux/tagent.service out/installer/tagent.service
	cp dist/linux/tagent_init.service out/installer/tagent_init.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/module_analysis.sh out/installer/module_analysis.sh && chmod +x out/installer/module_analysis.sh
	cp dist/linux/module_analysis_da.sh out/installer/module_analysis_da.sh && chmod +x out/installer/module_analysis_da.sh
	cp dist/linux/module_analysis_da_tcg.sh out/installer/module_analysis_da_tcg.sh && chmod +x out/installer/module_analysis_da_tcg.sh
	cp dist/linux/manifest_tpm20.xml out/installer/manifest_tpm20.xml
	cp dist/linux/manifest_wlagent.xml out/installer/manifest_wlagent.xml

	cd tboot-xm && $(MAKE) package
	cp tboot-xm/out/application-agent*.bin out/installer/
	
	cp out/tagent out/installer/tagent
	makeself out/installer out/trustagent-$(VERSION).bin "TrustAgent $(VERSION)" ./install.sh

build_test: gta
	export CGO_CFLAGS_ALLOW="-f.*" && cd resource && go test -c -o ../out/resource.test -tags=unit_test
	export CGO_CFLAGS_ALLOW="-f.*" && cd tasks && go test -c -o ../out/tasks.test -tags=unit_test

all: clean installer

clean:
	cd tboot-xm && $(MAKE) clean
	rm -rf out/
