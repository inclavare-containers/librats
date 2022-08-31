ifeq ($(LIBRATS_VERSION),)
$(error "Please run make package in the root directory")
endif

ifeq ($(LIBRATS_MAINTAINER),)
$(error "Please run make package in the root directory")
endif

PROJECT := librats
PROJECT_DIR := $(shell cd ../..; pwd)
RPMBUILD_DIR := $(shell mktemp -u /tmp/rpmbuild.XXXX)
RELEASE_TARBALL_FILE := $(RPMBUILD_DIR)/SOURCES/v$(LIBRATS_VERSION).tar.gz
RELEASE_TARBALL_EXIST := $(shell if [ -f $(RELEASE_TARBALL_FILE) ]; then echo "y"; else echo "n"; fi;)

release-tarball:
ifneq ($(RELEASE_TARBALL_EXIST), y)
	@mkdir -p $(RPMBUILD_DIR)/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	@cp -r $(PROJECT_DIR) $(RPMBUILD_DIR)/SOURCES/$(PROJECT)-$(LIBRATS_VERSION)
	@cd $(RPMBUILD_DIR)/SOURCES && tar -cvzf "v$(LIBRATS_VERSION).tar.gz" $(PROJECT)-$(LIBRATS_VERSION)
endif

rpm: rpm/librats.spec release-tarball
	@cp rpm/librats*-filelist $(RPMBUILD_DIR)/SOURCES
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba --define 'mode host' rpm/librats.spec
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba --define 'mode occlum' rpm/librats.spec
	@rpmbuild -D "_topdir $(RPMBUILD_DIR)" -ba --define 'mode sgx' rpm/librats.spec
	@cp $(RPMBUILD_DIR)/RPMS/x86_64/*.rpm $(PROJECT_DIR)/$(PROJECT)
	@rm -rf $(RPMBUILD_DIR)
	@echo "the rpms of librats located in $(PROJECT_DIR)/$(PROJECT)"

package: rpm/librats.spec.in 
ifeq (/etc/redhat-release, $(wildcard /etc/redhat-release))
	sed 's/Version: %{LIBRATS_VERSION}/Version: $(LIBRATS_VERSION)/' rpm/librats.spec.in > rpm/librats.spec && egrep -q '^\* .+ - $(LIBRATS_VERSION)' rpm/librats.spec || { \
	date=`date "+%a %b %d %Y"` && \
	sed -i "/%changelog/a* $$date $(LIBRATS_MAINTAINER) - $(LIBRATS_VERSION)\n- Update to version $(LIBRATS_VERSION)\n" rpm/librats.spec; };
	make rpm
else
	@echo "error! don't support generating packages on this system"
endif

.PHONY: release-tarball rpm package