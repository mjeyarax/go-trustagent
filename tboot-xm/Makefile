VERSION = 4.6
TBOOT-PACKAGE-NAME= tbootxm-zip-$(VERSION)-SNAPSHOT
APPLICATION-AGENT-PACKAGE-NAME = application-agent-$(VERSION)-SNAPSHOT
LIBWML-ARTIFACT-NAME = lib-workload-measurement-1.1.zip

.PHONY: build

build:
	cd src && $(MAKE)

tbootxm-zip: build
	mkdir -p out
	rm -rf out/$(TBOOT-PACKAGE-NAME)
	mkdir out/$(TBOOT-PACKAGE-NAME)

	mkdir out/$(TBOOT-PACKAGE-NAME)/bin
	cp bin/tpmextend out/$(TBOOT-PACKAGE-NAME)/bin
	cp bin/measure out/$(TBOOT-PACKAGE-NAME)/bin
	cp tcb_protection/configure_host.sh out/$(TBOOT-PACKAGE-NAME)/bin
	cp tcb_protection/generate_initrd.sh out/$(TBOOT-PACKAGE-NAME)/bin
	cp tcb_protection/tcb_protection_scripts/measure_host out/$(TBOOT-PACKAGE-NAME)/bin
	cp tcb_protection/tboot-xm-uninstall.sh out/$(TBOOT-PACKAGE-NAME)/bin

	mkdir out/$(TBOOT-PACKAGE-NAME)/lib
	cp lib/libwml.so out/$(TBOOT-PACKAGE-NAME)/lib
	cp tcb_protection/create_menuentry.pl out/$(TBOOT-PACKAGE-NAME)/lib
	cp tcb_protection/update_menuentry.pl out/$(TBOOT-PACKAGE-NAME)/lib
	cp tcb_protection/remove_menuentry.pl out/$(TBOOT-PACKAGE-NAME)/lib

	cp -r tcb_protection/dracut_files out/$(TBOOT-PACKAGE-NAME)
	cp -r tcb_protection/initrd_hooks out/$(TBOOT-PACKAGE-NAME)
	cp -r tcb_protection/mkinitrd_files out/$(TBOOT-PACKAGE-NAME)

	cd out/$(TBOOT-PACKAGE-NAME) && rm -rf tbootxm-zip*.zip
	cd out/$(TBOOT-PACKAGE-NAME) && zip -r $(TBOOT-PACKAGE-NAME).zip .

package: tbootxm-zip
	rm -rf out/$(APPLICATION-AGENT-PACKAGE-NAME)
	mkdir out/$(APPLICATION-AGENT-PACKAGE-NAME)

	cp out/$(TBOOT-PACKAGE-NAME)/$(TBOOT-PACKAGE-NAME).zip out/$(APPLICATION-AGENT-PACKAGE-NAME)
	cp makeself/setup.sh out/$(APPLICATION-AGENT-PACKAGE-NAME)
	chmod 755 out/$(APPLICATION-AGENT-PACKAGE-NAME)/setup.sh
	cp makeself/mtwilson-linux-util.sh out/$(APPLICATION-AGENT-PACKAGE-NAME)
	chmod 755 out/$(APPLICATION-AGENT-PACKAGE-NAME)/mtwilson-linux-util.sh

	makeself out/$(APPLICATION-AGENT-PACKAGE-NAME) out/$(APPLICATION-AGENT-PACKAGE-NAME)-rhel.bin "Application-Agent $(VERSION)" ./setup.sh

all: build

clean:
	cd src && $(MAKE) clean
	rm -rf out