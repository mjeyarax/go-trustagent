GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=iso-strict --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)
APPLICATION-AGENT-ARTIFACT = application-agent-4.6-SNAPSHOT-rhel.bin
GITLAB-TOKEN = gpgtQ5xyjKwDYECNjc9T
TBOOTXM-BRANCH = v1.0%2Fgo-trust-agent
TBOOTXM-PROJECT-ID = 21861

gta:
	env GOOS=linux go build -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/util.Version=$(VERSION) -X intel/isecl/go-trust-agent/util.GitHash=$(GITCOMMIT) -X intel/isecl/go-trust-agent/util.CommitDate=$(GITCOMMITDATE)" -o out/tagent

# KWT
# Pass the '-w' flag to the linker to omit the debug information (for example, go build -ldflags=-w prog.go).
# https://golang.org/doc/gdb
# https://gitlab.devtools.intel.com/sst/isecl/lib-java/lib-workload-measurement/commit/db18532cccb1aabce8444b1ed4844bf8e54d8915 ...
# -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIE -fPIC -fstack-protector-strong -O2 -D

package: gta
	mkdir -p out/installer
	cp dist/linux/tagent.service out/installer/tagent.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/module_analysis.sh out/installer/module_analysis.sh && chmod +x out/installer/module_analysis.sh
	cp dist/linux/module_analysis_da.sh out/installer/module_analysis_da.sh && chmod +x out/installer/module_analysis_da.sh
	cp dist/linux/module_analysis_da_tcg.sh out/installer/module_analysis_da_tcg.sh && chmod +x out/installer/module_analysis_da_tcg.sh
	cp dist/linux/manifest_tpm20.xml out/installer/manifest_tpm20.xml
	cp dist/linux/manifest_wlagent.xml out/installer/manifest_wlagent.xml
	
	# download and copy hex2bin to the installer so it is included in the trustagent installer
	# This will not work in github (ISECL-7447)
	if [ ! -f out/installer/hex2bin ] ; \
	then \
		curl -u kentthom:AKCp5e2qnfZBRirnKDcNizevt3fU2QYVvJL87T9nzfnrxWEQzPyuMGM63QHEYpL4dmbVsP1XT https://ubit-artifactory-or.intel.com/artifactory/mtwilson-local/com/intel/mtwilson/mtwilson-node-tools-zip/1.1/mtwilson-node-tools-zip-1.1.zip -o out/mtwilson-node-tools-zip-1.1.zip --noproxy '*'; \
		unzip -o out/mtwilson-node-tools-zip-1.1.zip -d out; \
		unzip -o out/hex2bin-dist-1.0-generic.zip -d out; \
		cp out/hex2bin/bin/hex2bin out/installer; \
	fi;


	# download and copy application-agent to the installer so it is included in the trustagent installer
	# This will not work in github (ISECL-7447)
	if [ ! -f out/installer/$(APPLICATION-AGENT-ARTIFACT) ] ; \
	then \
		curl --header 'PRIVATE-TOKEN: $(GITLAB-TOKEN)' https://gitlab.devtools.intel.com/api/v4/projects/$(TBOOTXM-PROJECT-ID)/jobs/artifacts/$(TBOOTXM-BRANCH)/raw/out/$(APPLICATION-AGENT-ARTIFACT)?job=tbootxm --noproxy '*' --out out/installer/$(APPLICATION-AGENT-ARTIFACT) --noproxy '*'; \
	fi;

	cp out/tagent out/installer/tagent
	makeself out/installer out/trustagent-$(VERSION).bin "TrustAgent $(VERSION)" ./install.sh

build_test: gta
	cd resource && go test -c -o ../out/resource.test -tag=unit_test
	cd tasks && go test -c -o ../out/tasks.test -tags=unit_test

all: gt

clean:
	rm -f cover.*
	rm -rf out/
	rm -rf builds/