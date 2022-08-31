# Root directory of the project (absolute path).
ROOTDIR=$(dir $(abspath $(lastword $(MAKEFILE_LIST))))
LIBRATS_VERSION := $(shell cat $(ROOTDIR)/VERSION)
LIBRATS_MAINTAINER := $(shell head -1 $(ROOTDIR)/MAINTAINERS)
Librats_Libdir := /usr/local/lib/librats
Librats_Incdir := /usr/local/include/librats
Librats_Bindir:= /usr/share/librats

all:
	cmake -DBUILD_SAMPLES=on -H. -Bbuild
	make -C build

clean:
	@make -C build clean
	@rm -f dist/rpm/librats.spec 

install:
	cmake -DBUILD_SAMPLES=on -H. -Bbuild
	make -C build install

uninstall:
	@rm -rf $(Librats_Libdir) $(Librats_Incdir) $(Librats_Bindir)

package:
	$(MAKE) -C dist package LIBRATS_VERSION="$(LIBRATS_VERSION)" LIBRATS_MAINTAINER="$(LIBRATS_MAINTAINER)"