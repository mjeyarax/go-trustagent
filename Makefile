GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
GITBRANCH := $(shell git rev-parse --abbrev-ref HEAD)
BUILDDATE := $(shell TZ=UTC date +%Y-%m-%dT%H:%M:%SZ)
VERSION := $(or ${GITTAG}, v1.0.0)
APPLICATION-AGENT-ARTIFACT = application-agent-4.6-SNAPSHOT-rhel.bin
GITLAB-TOKEN = gpgtQ5xyjKwDYECNjc9T
TBOOTXM-BRANCH = v1.0%2Fgo-trust-agent
TBOOTXM-PROJECT-ID = 21861

# TODO:  Update make file to support debug/release builds (release build to use secure gcflags)
# See https://gitlab.devtools.intel.com/sst/isecl/lib-java/lib-workload-measurement/commit/db18532cccb1aabce8444b1ed4844bf8e54d8915 ...
# -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIE -fPIC -fstack-protector-strong -O2 -D
gta:
	env GOOS=linux go build -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/util.Version=$(VERSION) -X intel/isecl/go-trust-agent/util.GitHash=$(GITCOMMIT) -X intel/isecl/go-trust-agent/util.BuildDate=$(BUILDDATE)" -o out/tagent

package: gta
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
	cd resource && go test -c -o ../out/resource.test -tags=unit_test
	cd tasks && go test -c -o ../out/tasks.test -tags=unit_test

all: clean package

clean:
	cd tboot-xm && $(MAKE) clean
	rm -rf out/
