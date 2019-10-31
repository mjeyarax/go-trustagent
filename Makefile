GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
GITCOMMITDATE := $(shell git log -1 --date=iso-strict --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v1.0.0)

gta:
	env GOOS=linux go build -gcflags=all="-N -l" -ldflags "-X intel/isecl/go-trust-agent/version.Version=$(VERSION) -X intel/isecl/go-trust-agent/version.GitHash=$(GITCOMMIT) -X intel/isecl/go-trust-agent/version.CommitDate=$(GITCOMMITDATE)" -o out/tagent

# KWT
# Pass the '-w' flag to the linker to omit the debug information (for example, go build -ldflags=-w prog.go).
# https://golang.org/doc/gdb
# https://gitlab.devtools.intel.com/sst/isecl/lib-java/lib-workload-measurement/commit/db18532cccb1aabce8444b1ed4844bf8e54d8915 ...
# -fno-strict-overflow -fno-delete-null-pointer-checks -fwrapv -fPIE -fPIC -fstack-protector-strong -O2 -D

installer: gta
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
		wget -O out/mtwilson-node-tools-zip-1.1.zip https://ubit-artifactory-or.intel.com/artifactory/mtwilson-local/com/intel/mtwilson/mtwilson-node-tools-zip/1.1/mtwilson-node-tools-zip-1.1.zip --user=kentthom --password='d!sc0ntentCart' --no-proxy; \
		unzip -o out/mtwilson-node-tools-zip-1.1.zip -d out; \
		unzip -o out/hex2bin-dist-1.0-generic.zip -d out; \
		cp out/hex2bin/bin/hex2bin out/installer; \
	fi;

	# download and copy application-agent to the installer so it is included in the trustagent installer
	# This will not work in github (ISECL-7447)
	if [ ! -f out/installer/application-agent-4.6-SNAPSHOT-rhel.bin ] ; \
	then \
		wget -O out/installer/application-agent-4.6-SNAPSHOT-rhel.bin https://ubit-artifactory-or.intel.com/artifactory/mtwilson-local/com/intel/mtwilson/tbootxm/packages/application-agent/4.6-SNAPSHOT/application-agent-4.6-SNAPSHOT-rhel.bin --user=kentthom --password='d!sc0ntentCart' --no-proxy; \
	fi;

	cp out/tagent out/installer/tagent
	makeself out/installer out/trustagent-$(VERSION).bin "TrustAgent $(VERSION)" ./install.sh

build_test: gta
	cd resource && go test -c -o ../out/resource.test
	cd tasks && go test -c -o ../out/tasks.test

all: gt

clean:
	rm -f cover.*
	rm -rf out/
	rm -rf builds/