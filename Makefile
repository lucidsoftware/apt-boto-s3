JOBS ?= 4

MAKEFLAGS += -r -j $(JOBS)

.ONESHELL:

.PHONY: dist
dist: target/apt_boto_s3.deb

.PHONY: install
install: target/apt_boto_s3.deb
	dpkg -i $<

.PHONY: clean
clean:
	rm -fr target

DEBIAN_SRCS := $(wildcard debian/*)
DEBIAN_TARGETS := $(DEBIAN_SRCS:debian/%=target/apt_boto_s3/DEBIAN/%)

target/apt_boto_s3/usr/lib/apt/methods/s3: s3.py
	@mkdir -p $(@D)
	cp --preserve=mode $< $@

$(DEBIAN_TARGETS): target/apt_boto_s3/DEBIAN/%: debian/%
	@mkdir -p $(@D)
	cp --preserve=mode $< $@

target/apt_boto_s3.deb: $(DEBIAN_TARGETS) target/apt_boto_s3/usr/lib/apt/methods/s3
	fakeroot dpkg-deb --build target/apt_boto_s3 $@
