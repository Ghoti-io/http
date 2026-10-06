SUITE := ghoti.io
PROJECT := http

BUILD ?= release
# The version of this library. MINOR_VERSION carries the minor and the patch as
# one dotted string; the two are split out below for the places that need three
# separate integers. See CONVENTIONS.md section 4.
MAJOR_VERSION := 0
MINOR_VERSION := 0.0
VERSION_MINOR_ONLY := $(word 1,$(subst ., ,$(MINOR_VERSION)))
VERSION_PATCH_ONLY := $(or $(word 2,$(subst ., ,$(MINOR_VERSION))),0)
# Substituted into the .pc file; an empty Version: field makes every
# pkg-config version constraint fail.
VERSION := $(MAJOR_VERSION).$(MINOR_VERSION)

# Names this build everywhere: the .pc file, the install directory, the soname
# and the symbol token. It defaults to the major version, so an ordinary build
# of 1.x is "-1" and two majors cannot be loaded into one process by mistake.
# Override it for a build that wants its own identity:  make BRANCH=-dev
BRANCH ?= -$(MAJOR_VERSION)

# What the library reports as its version. The branch is appended only when it
# is not the default, so an ordinary build says "1.2.3" and an overridden one
# says "1.2.3-dev". Computed before BUILD=debug rewrites BRANCH below.
ifeq ($(BRANCH),-$(MAJOR_VERSION))
VERSION_STRING := $(VERSION)
else
VERSION_STRING := $(VERSION)$(BRANCH)
endif

# If BUILD is debug, append -debug.
#
# "override" because BRANCH may have come from the command line, and a
# command-line variable otherwise wins over a plain assignment here: without it
# `make BRANCH=-dev BUILD=debug` produced a debug build carrying the release
# token, whose symbols collide with the release build's.
ifeq ($(BUILD),debug)
    override BRANCH := $(BRANCH)-debug
    override VERSION_STRING := $(VERSION_STRING)-debug
endif

# The optimisation level, decided here rather than written into CFLAGS.
#
# Two reasons this block is *here*, above the platform rewrite below, rather
# than next to CFLAGS where it is used. `BUILD := linux/$(BUILD)` further down
# is a plain assignment, so a command-line `BUILD=debug` overrides it and BUILD
# stays "debug", while an environment `BUILD=debug` does not and it becomes
# "linux/debug". Testing BUILD up here, before anything rewrites it, is true in
# both cases.
#
# Until 2026-09-23 this library compiled its release build at -O0 and its debug
# build at -O0 as well, because the debug block above renamed the artifact and
# changed nothing about how anything was compiled. So `make BUILD=debug`
# produced a differently-named copy of the release build, and the release build
# was never optimised. Neither was decided; the -O0 is older than the
# repository and was copied in from a project where the production build
# doubled as the debugging build.
ifeq ($(BUILD),debug)
OPT_CFLAGS := -O0
else
OPT_CFLAGS := -O2
endif

BASE_NAME := lib$(SUITE)-$(PROJECT)$(BRANCH).so
# The symbol namespace token, from BRANCH, so that the token inside every
# exported symbol is the same one that names the .pc file, the install directory
# and the shared library. See CONVENTIONS.md section 4.
LIBVER_SYMBOL := $(shell echo "ghotiio_$(PROJECT)$(BRANCH)" | sed 's/[.-]/_/g')

BASE_NAME_PREFIX := lib$(SUITE)-$(PROJECT)$(BRANCH)
SO_NAME := $(BASE_NAME).$(MAJOR_VERSION)
STATIC_TARGET := $(BASE_NAME_PREFIX).a
ENV_VARS :=

# PC_INSTALL_PATH names where this project's own .pc file is installed.
# PKG_CONFIG_PATH is the environment's and is never assigned here: make exports
# an inherited variable with whatever value the makefile last gave it, so
# overwriting it handed every sub-make a different PKG_CONFIG_PATH from the
# parent's. The sub-make then derived different flags, found the flag stamp
# changed, and rebuilt everything - which check-rebuild reports as a settled
# tree that will not settle. It showed first under MSYS2, whose login shell
# exports PKG_CONFIG_PATH, and happens on Linux whenever the exported value is
# not exactly the install location. cutil made the same change.
PKG_CONFIG_PATH_ENV := $(PKG_CONFIG_PATH)

# `override` on each of those: BUILD may arrive on the command line, and a
# command-line variable beats a plain makefile assignment, so without it
# `make BUILD=debug` skips the rewrite and builds into ./build/debug --
# outside the platform tree, and a different tree from the one plain `make`
# uses. The platform segment exists to keep linux/mac/win builds apart.

# Detect OS
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S), Linux)
	OS_NAME := Linux
	LIB_EXTENSION := so
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG := -Wl,-soname,$(SO_NAME)
	TARGET := $(SO_NAME).$(MINOR_VERSION)
	EXE_EXTENSION :=
	# Additional Linux-specific variables
	PC_INSTALL_PATH := /usr/local/share/pkgconfig
	INCLUDE_INSTALL_PATH := /usr/local/include
	LIB_INSTALL_PATH := /usr/local/lib
	PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
	override BUILD := linux/$(BUILD)

else ifeq ($(UNAME_S), Darwin)
	OS_NAME := Mac
	LIB_EXTENSION := dylib
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG := -Wl,-install_name,$(BASE_NAME_PREFIX).dylib
	TARGET := $(BASE_NAME_PREFIX).dylib
	EXE_EXTENSION :=
	# Additional macOS-specific variables
	PC_INSTALL_PATH := /usr/local/share/pkgconfig
	INCLUDE_INSTALL_PATH := /usr/local/include
	LIB_INSTALL_PATH := /usr/local/lib
	PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
	override BUILD := mac/$(BUILD)

else ifeq ($(findstring MINGW32_NT,$(UNAME_S)),MINGW32_NT)  # 32-bit Windows
	OS_NAME := Windows
	LIB_EXTENSION := dll
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG = -Wl,--out-implib,$(APP_DIR)/$(BASE_NAME_PREFIX).dll.a
	TARGET := $(BASE_NAME_PREFIX).dll
	EXE_EXTENSION := .exe
	# Additional Windows-specific variables
	# This is the path to the pkg-config files on MSYS2
	PC_INSTALL_PATH := /mingw32/lib/pkgconfig
	INCLUDE_INSTALL_PATH := /mingw32/include
	LIB_INSTALL_PATH := /mingw32/lib
	BIN_INSTALL_PATH := /mingw32/bin
	# Windows paths for .pc so gcc invoked by mingw can resolve -I/-L (cygpath for MSYS2)
	PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
	PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
	override BUILD := win32/$(BUILD)

# TODO(windows): the Windows branches in this file were adapted from image's
# and have never been run, nor has GHTTP_API's dllexport/dllimport switching.
else ifeq ($(findstring MINGW64_NT,$(UNAME_S)),MINGW64_NT)  # 64-bit Windows
	OS_NAME := Windows
	LIB_EXTENSION := dll
	OS_SPECIFIC_CXX_FLAGS := -shared
	OS_SPECIFIC_LIBRARY_NAME_FLAG = -Wl,--out-implib,$(APP_DIR)/$(BASE_NAME_PREFIX).dll.a
	TARGET := $(BASE_NAME_PREFIX).dll
	EXE_EXTENSION := .exe
	# Additional Windows-specific variables
	# This is the path to the pkg-config files on MSYS2
	PC_INSTALL_PATH := /mingw64/lib/pkgconfig
	INCLUDE_INSTALL_PATH := /mingw64/include
	LIB_INSTALL_PATH := /mingw64/lib
	BIN_INSTALL_PATH := /mingw64/bin
	# Windows paths for .pc so gcc invoked by mingw can resolve -I/-L (cygpath for MSYS2)
	PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
	PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
	override BUILD := win64/$(BUILD)

else
    $(error Unsupported OS: $(UNAME_S))

endif

# ---------------------------------------------------------------------------
# Installation prefix
#
# Defaults to the system location chosen above. Override it to install
# somewhere else - the suite's bootstrap installs every library into a local
# prefix so that each build resolves its dependencies through pkg-config,
# exactly as a consumer would, rather than through a second code path that
# only in-tree builds exercise. See CONVENTIONS.md section 1.
#
#     make install PREFIX=/path/to/prefix
# ---------------------------------------------------------------------------
ifdef PREFIX
INCLUDE_INSTALL_PATH := $(PREFIX)/include
LIB_INSTALL_PATH := $(PREFIX)/lib
BIN_INSTALL_PATH := $(PREFIX)/bin
PC_INSTALL_PATH := $(PREFIX)/share/pkgconfig
ifeq ($(OS_NAME), Windows)
PC_INCLUDE_DIR = $(shell cygpath -m $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH))
PC_LIB_DIR = $(shell cygpath -m $(LIB_INSTALL_PATH)/$(SUITE))
else
PC_INCLUDE_DIR := $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
PC_LIB_DIR := $(LIB_INSTALL_PATH)/$(SUITE)
endif
# A non-system prefix has no /etc/ld.so.conf.d, and writing to it would need
# root anyway. Everything built here carries an rpath to the prefix instead.
LDCONF_INSTALL_PATH :=
endif

# Dependencies are looked up along the inherited PKG_CONFIG_PATH as well as the
# install location chosen above, so that exporting PKG_CONFIG_PATH works as the
# errors below say it does. The inherited value comes first: it is an explicit
# request for this build, where the install location may be only a default.
PKG_CONFIG_LOOKUP_PATH := $(if $(PKG_CONFIG_PATH_ENV),$(PKG_CONFIG_PATH_ENV):)$(PC_INSTALL_PATH)


CXX := g++
CXXFLAGS := -pedantic-errors -Wall -Wextra -Werror -Wno-error=unused-function -Wfatal-errors -std=c++20 -O1 -g $(EXTRA_CXXFLAGS)
CC := cc
# -Wfloat-conversion and -Wstrict-aliasing=1 catch what no sanitizer does: an
# implicit float-to-integer conversion, and a type-punned store. -fstrict-
# aliasing is named explicitly because the warning is silent without it and
# gcc only enables it from -O2. The level is not readable off the flag list,
# so check-aliasing asks the compiler (the table of measured precedence is in
# model's Makefile, from which this one was copied). To build the debug tree
# against a release prefix: make BUILD=debug CUTIL_PC=ghoti.io-cutil-$(MAJOR_VERSION)
CFLAGS := -pedantic-errors -Wall -Wextra -Werror -Wfloat-conversion -fstrict-aliasing -Wstrict-aliasing=1 -Wno-error=unused-function -Wfatal-errors -std=c17 $(OPT_CFLAGS) -g $(EXTRA_CFLAGS)
# Library-specific compile flags (export symbols on Windows, PIC on Linux)
# GHTTP_BUILD enables DLL export on Windows (checked by GHTTP_API macro)
# GHTTP_TEST_BUILD enables export of internal functions for testing (checked by GHTTP_INTERNAL_API macro)
# No -DGHTTP_TEST_BUILD: the shipped library exports its public API and nothing
# else. Tests reach the internals by linking the static archive, which a static
# link can do even for hidden symbols.
ifeq ($(OS_NAME), Windows)
# Everything built here but the library itself links the static archive, so
# the headers must not say dllimport to it: an archive has no __imp_ thunks.
# The library's own objects also get GHTTP_BUILD, which the header tests first.
# See GHTTP_API in macros.h.
CFLAGS += -DGHTTP_STATIC
CXXFLAGS += -DGHTTP_STATIC
endif
LIB_CFLAGS := $(CFLAGS) -fvisibility=hidden -DGHTTP_BUILD $(EXTRA_CFLAGS)
LDFLAGS := -L /usr/lib -lstdc++ -lm $(EXTRA_LDFLAGS)
ifdef PREFIX
# So that a library, a test or an example finds its Ghoti.io dependencies in the
# prefix at run time without LD_LIBRARY_PATH.
LDFLAGS += -Wl,-rpath,$(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Windows)
# Windows has no rpath: a program finds its DLLs through PATH. Putting the
# prefix's bin/ on it for everything make runs is the equivalent, so that a
# test or an example finds its dependencies without the caller arranging it.
# Without this they die before main() with 0xC0000135 and make reports 127.
export PATH := $(BIN_INSTALL_PATH):$(PATH)
endif
endif

BUILD_DIR := ./build/$(BUILD)
OBJ_DIR := $(BUILD_DIR)/objects
FLAGS_STAMP := $(OBJ_DIR)/.flags
GEN_DIR := $(BUILD_DIR)/generated
APP_DIR := $(BUILD_DIR)/apps


# Add OS-specific flags
ifeq ($(UNAME_S), Linux)
	LIB_CFLAGS += -fPIC

else ifeq ($(UNAME_S), Darwin)

else ifeq ($(findstring MINGW32_NT,$(UNAME_S)),MINGW32_NT)  # 32-bit Windows

else ifeq ($(findstring MINGW64_NT,$(UNAME_S)),MINGW64_NT)  # 64-bit Windows

else
	$(error Unsupported OS: $(UNAME_S))

endif

# The standard include directories for the project.
INCLUDE := -I include/ -I $(GEN_DIR)/

# Goals that compile and link nothing.  A missing sibling library must not stop
# them: `make docs` needs doxygen and the tracked sources, not cutil, and it
# was failing at parse time - before doxygen was ever reached - on any machine
# where the suite is not installed.  Every other goal still gets the hard
# error below, which is the point of having no fallback.
DEPLESS_GOALS := docs docs-pdf clean fuzz-clean cloc help
ifeq ($(filter-out $(DEPLESS_GOALS),$(or $(MAKECMDGOALS),all)),)
SKIP_DEP_CHECK := 1
endif

# ghoti.io-cutil, for the allocator vtable, the growable array, and the
# overflow-checked size math. Prefer pkg-config; fall back to a sibling
# checkout. The name must carry $(BRANCH): cutil installs its .pc as
# ghoti.io-cutil-dev.pc, so asking for "ghoti.io-cutil" never matches.
CUTIL_PC ?= ghoti.io-cutil$(BRANCH)
CUTIL_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --cflags $(CUTIL_PC) 2>/dev/null)
CUTIL_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs $(CUTIL_PC) 2>/dev/null)
# An empty answer means pkg-config could not find it. There is no second
# resolution path to fall back to, so this is a hard error naming the fix.
ifeq ($(strip $(CUTIL_CFLAGS)),)
ifndef SKIP_DEP_CHECK
$(error ghoti.io-cutil was not found by pkg-config. Run ./bootstrap.sh at the root of the workspace - two levels up, the directory holding libs/ - to build and install the suite into a local prefix, then pass the same PREFIX here - or point PKG_CONFIG_PATH at the directory holding its .pc file. There is deliberately no sibling-checkout fallback: a second resolution path that only in-tree builds exercise is one that silently rots.)
endif
endif
INCLUDE += $(CUTIL_CFLAGS)

# Automatically collect all .c source files under the src directory.
SOURCES := $(shell find src -type f -name '*.c')

# Convert each source file path to an object file path.
LIBOBJECTS := $(patsubst src/%.c,$(OBJ_DIR)/%.o,$(SOURCES))

TESTFLAGS := `PKG_CONFIG_PATH=$(PKG_CONFIG_LOOKUP_PATH) pkg-config --libs --cflags gtest`

# The checks `make test` runs besides the tests themselves. Named in a
# variable so that a build which cannot satisfy them can clear it: the
# coverage target does, because --coverage links the gcov runtime, whose
# mangle_path check-symbols is right to reject in a shipping library and
# wrong to reject in an instrumented one. Spelled as text's TEST_GATES is.
TEST_GATES ?= check-symbols check-aliasing check-defects

# Valgrind flags (exclude "still reachable" as it's not a leak)
# --suppressions: see tests/valgrind.supp. It holds allocations that are
# demonstrably glibc's rather than ours, each with the evidence that its
# frames are narrow enough not to hide a leak of our own.
VALGRIND_FLAGS := --leak-check=full --show-leak-kinds=definite,indirect,possible --track-origins=yes --error-exitcode=1 --suppressions=tests/valgrind.supp

####################################################################
# Test discovery
####################################################################

# Optional shared test helper (if present).
TEST_HELPER_SRC := $(wildcard tests/test_helpers.cpp)
TEST_HELPER_OBJ := $(patsubst tests/%.cpp,$(OBJ_DIR)/tests/%.o,$(TEST_HELPER_SRC))

# The static archive, not -l: a static link resolves hidden symbols, so the
# tests can exercise internals the shared library does not export.
# --whole-archive because anything registering itself from a constructor is
# otherwise dropped - a plain archive link only pulls in object files that
# something references by name.
HTTPLIBRARY := -Wl,--whole-archive $(APP_DIR)/$(STATIC_TARGET) -Wl,--no-whole-archive $(CUTIL_LIBS)

# Windows has no fopencookie, so FailingSink (tests/test_helpers.h) serves its
# failures from a wrapper around the library's fprintf instead of from the
# stream. MinGW's headers spell fprintf __mingw_fprintf in C.
ifeq ($(OS_NAME), Windows)
TEST_LDFLAGS := -Wl,--wrap=__mingw_fprintf
else
TEST_LDFLAGS :=
endif

# Discover test sources and compute an executable name for each, as
# "path|name" pairs. test_foo.cpp -> testFoo.
TEST_PAIRS := $(shell find tests -type f -name 'test_*.cpp' 2>/dev/null | sort | grep -v test_helpers | while read f; do \
	echo "$$f|$$(basename "$$f" .cpp | sed 's/test_/test/; s/^test\([a-z]\)/test\U\1/')"; done)
TEST_SOURCES := $(foreach pair,$(TEST_PAIRS),$(word 1,$(subst |, ,$(pair))))
TEST_NAMES := $(foreach pair,$(TEST_PAIRS),$(word 2,$(subst |, ,$(pair))))
TEST_EXECUTABLES := $(addprefix $(APP_DIR)/,$(addsuffix $(EXE_EXTENSION),$(TEST_NAMES)))

# Automatically collect all example .c files.
EXAMPLE_SOURCES := $(shell find examples -type f -name '*.c' 2>/dev/null)
EXAMPLES := $(patsubst examples/%.c,$(APP_DIR)/examples/%$(EXE_EXTENSION),$(EXAMPLE_SOURCES))


all: $(APP_DIR)/$(TARGET) $(APP_DIR)/$(STATIC_TARGET) ## Build shared + static libraries

####################################################################
# Dependency Inclusion
####################################################################

TEST_DEPFILES := $(foreach pair,$(TEST_PAIRS),$(OBJ_DIR)/tests/$(basename $(notdir $(word 1,$(subst |, ,$(pair))))).d)
# The ASan tree needs these as much as the release tree does, and did not
# have them. A header change therefore left its objects stale: adding a
# field to GHTTP_Limits and running `make test-asan` reported
# "AddressSanitizer: unknown-crash ... in ghttp_limits_default", which reads
# as a defect in the library and was a struct written by new code into a
# buffer sized by old code. A clean rebuild passed. That failure mode is
# worse than a stale result, because the report names a source line and
# accuses working code.
DEPFILES := $(LIBOBJECTS:.o=.d) $(TEST_HELPER_OBJ:.o=.d) $(TEST_DEPFILES)
-include $(DEPFILES)

####################################################################
# Object Files
####################################################################

####################################################################
# Generated version header
####################################################################

LIBVER_GEN := $(GEN_DIR)/ghoti.io/$(PROJECT)/libver_gen.h
# EVERY rule that compiles a translation unit carries `| $(LIBVER_GEN)`, not
# just the release library's. Each one reaches this generated header -
# macros.h includes namespace.h includes libver.h includes libver_gen.h - so
# a rule without it works only on a tree where something else already
# generated the file. That is the worst shape a build defect takes: it passes
# for everyone who has built before and fails for everyone who has not, and
# under -j it is a race rather than a clean failure.
#
# CONVENTIONS.md section 6 states the rule and section 12 warns that copying
# a Makefile copies its defects. This is that: the release rule had it and
# the ASan, fuzz and test rules did not, so `make test` passed on any warm
# tree while `make clean && make test-asan` failed on all of them.

# libver_gen.h is regenerated on every build and rewritten only when its content
# changes, so a variable given on the command line - make MAJOR_VERSION=2, or
# make BRANCH=-dev - takes effect. Keying the rule on the Makefile's timestamp
# alone left the previous token and version baked into the build, and nothing
# said so.
.PHONY: force-libver
force-libver:

$(LIBVER_GEN): force-libver
	@if [ -z "$(LIBVER_SYMBOL)" ]; then \
		printf "### LIBVER_SYMBOL is empty ###\n" >&2; \
		printf "Every exported symbol would lose its version namespace.\n" >&2; \
		exit 1; \
	fi
	@mkdir -p $(@D)
	@printf '%s\n' \
		'// Generated by the Makefile. Do not edit; see CONVENTIONS.md section 4.' \
		'#ifndef GHOTI_IO_GHTTP_LIBVER_GEN_H' \
		'#define GHOTI_IO_GHTTP_LIBVER_GEN_H' \
		'' \
		'/** The symbol namespace for this build, from the Makefile'"'"'s BRANCH. */' \
		'#define GHOTIIO_HTTP_NAME $(LIBVER_SYMBOL)' \
		'' \
		'/** Human-readable version of this build. */' \
		'#define GHOTIIO_HTTP_VERSION "$(VERSION_STRING)"' \
		'' \
		'/** The same version as three integers. */' \
		'#define GHOTIIO_HTTP_VERSION_MAJOR $(MAJOR_VERSION)' \
		'#define GHOTIIO_HTTP_VERSION_MINOR $(VERSION_MINOR_ONLY)' \
		'#define GHOTIIO_HTTP_VERSION_PATCH $(VERSION_PATCH_ONLY)' \
		'' \
		'#endif // GHOTI_IO_GHTTP_LIBVER_GEN_H' > $@.tmp
	@if cmp -s $@.tmp $@; then rm -f $@.tmp; else mv $@.tmp $@; fi

$(OBJ_DIR)/%.o: src/%.c $(FLAGS_STAMP) | $(LIBVER_GEN)
	@printf "\n### Compiling $@ ###\n"
	@mkdir -p $(@D)
	$(CC) $(LIB_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

####################################################################
# Shared Library
####################################################################

$(APP_DIR)/$(TARGET): $(LIBOBJECTS)
	@printf "\n### Compiling HTTP Library ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) -shared -o $@ $^ $(LDFLAGS) $(CUTIL_LIBS) $(OS_SPECIFIC_LIBRARY_NAME_FLAG)

ifeq ($(OS_NAME), Linux)
	@ln -f -s $(TARGET) $(APP_DIR)/$(SO_NAME)
	@ln -f -s $(SO_NAME) $(APP_DIR)/$(BASE_NAME)
endif

####################################################################
# Static Library
####################################################################

$(APP_DIR)/$(STATIC_TARGET): $(LIBOBJECTS)
	@printf "\n### Archiving Static HTTP Library ###\n"
	@mkdir -p $(@D)
	@rm -f $@
	ar rcs $@ $^

####################################################################
# Unit Tests
####################################################################

ifneq ($(TEST_HELPER_SRC),)
$(TEST_HELPER_OBJ): $(TEST_HELPER_SRC) $(FLAGS_STAMP)
	@printf "\n### Compiling Test Helper ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@
endif

# Test sources live in tests/ and tests/unit/; the object name comes from the
# basename either way, so the executable name matches.
$(OBJ_DIR)/tests/%.o: tests/%.cpp $(FLAGS_STAMP) | $(LIBVER_GEN)
	@printf "\n### Compiling Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -Itests -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(OBJ_DIR)/tests/%.o: tests/unit/%.cpp $(FLAGS_STAMP) | $(LIBVER_GEN)
	@printf "\n### Compiling Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -Itests -c $< -MMD -MP -MF $(@:.o=.d) -o $@

# Build rule for one test executable. $1 = source path, $2 = executable name.
# Tests compile to .o first and link separately, so a library change relinks
# without recompiling every test.
#
# The archive is a normal prerequisite because that is what the link line
# uses, and a change to the library therefore relinks the tests. Naming only
# the shared library here - which is what this rule used to do - left nothing
# in the chain that builds the archive, so `make test` failed outright on a
# clean tree and raced under -j. The .so is order-only: it is not linked, but
# check-symbols and the test run both want it built.
define test-executable-rule
TEST_OBJ_$1 := $(OBJ_DIR)/tests/$(basename $(notdir $1)).o

$(APP_DIR)/$2$(EXE_EXTENSION): $$(TEST_OBJ_$1) $(TEST_HELPER_OBJ) \
		$(APP_DIR)/$(STATIC_TARGET) | $(APP_DIR)/$(TARGET)
	@printf "\n### Linking Test: $2 ###\n"
	@mkdir -p $$(@D)
	$(CXX) $(CXXFLAGS) -o $$@ $$(TEST_OBJ_$1) $(TEST_HELPER_OBJ) $(LDFLAGS) $(TEST_LDFLAGS) $(HTTPLIBRARY) $(CUTIL_LIBS) $(TESTFLAGS)
endef

$(foreach pair,$(TEST_PAIRS),\
	$(eval $(call test-executable-rule,$(word 1,$(subst |, ,$(pair))),$(word 2,$(subst |, ,$(pair))))))

####################################################################
# Examples
####################################################################

# Links the archive, so it depends on the archive; see test-executable-rule.
$(APP_DIR)/examples/%$(EXE_EXTENSION): examples/%.c $(APP_DIR)/$(STATIC_TARGET) \
		$(FLAGS_STAMP) | $(APP_DIR)/$(TARGET)
	@printf "\n### Compiling Example: $* ###\n"
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $< $(LDFLAGS) $(HTTPLIBRARY) $(CUTIL_LIBS)

####################################################################
# Commands
####################################################################

# General commands
.PHONY: clean cloc docs docs-pdf examples coverage check-symbols check-aliasing check-defects
# Release build commands
.PHONY: all install test test-quiet test-asan test-valgrind test-valgrind-quiet test-watch uninstall watch
# Debug build commands
.PHONY: all-debug install-debug test-debug test-valgrind-debug test-watch-debug uninstall-debug watch-debug
# Fuzz commands
.PHONY: fuzz fuzz-clean

watch: ## Watch the file directory for changes and compile the target
	@while true; do \
		make --no-print-directory all; \
		printf "\033[0;32m\n"; \
		printf "#########################\n"; \
		printf "# Waiting for changes.. #\n"; \
		printf "#########################\n"; \
		printf "\033[0m\n"; \
		inotifywait -qr -e modify -e create -e delete -e move src include tests Makefile --exclude '/\.'; \
		done

test-watch: ## Watch the file directory for changes and run the unit tests
	@while true; do \
		make --no-print-directory all; \
		make --no-print-directory test; \
		printf "\033[0;32m\n"; \
		printf "#########################\n"; \
		printf "# Waiting for changes.. #\n"; \
		printf "#########################\n"; \
		printf "\033[0m\n"; \
		inotifywait -qr -e modify -e create -e delete -e move src include tests Makefile --exclude '/\.'; \
		done

examples: ## Build all examples
examples: $(APP_DIR)/$(TARGET) $(EXAMPLES)
	@printf "\033[0;32m\n"
	@printf "############################\n"
	@printf "### Examples built       ###\n"
	@printf "############################\n"
	@printf "\033[0m\n"
	@printf "Examples are available in: $(APP_DIR)/examples/\n"
	@printf "\n"
	@printf "\033[0;33mTo run examples:\033[0m\n"
ifeq ($(OS_NAME), Linux)
	@printf "  Linux: Set LD_LIBRARY_PATH to include the library directory:\n"
	@printf "    export LD_LIBRARY_PATH=\"$(TEST_LD_PATH)\"\n"
	@printf "    $(APP_DIR)/examples/<example>\n"
else ifeq ($(OS_NAME), Mac)
	@printf "  macOS: Set DYLD_LIBRARY_PATH to include the library directory:\n"
	@printf "    export DYLD_LIBRARY_PATH=\"$(TEST_LD_PATH)\"\n"
	@printf "    $(APP_DIR)/examples/<example>\n"
else ifeq ($(OS_NAME), Windows)
	@printf "  Windows (MSYS2): The DLL must be in the same directory or in PATH.\n"
	@printf "    cd $(APP_DIR) && ./examples/<example>$(EXE_EXTENSION)\n"
endif
	@printf "\n"

# So the tests can load the http library and its dependency on cutil. cutil's
# build tree has no release/debug component, so only the leading OS component
# of BUILD applies to it.
TEST_LD_PATH := $(APP_DIR):$(LIB_INSTALL_PATH)/$(SUITE)

####################################################################
# Symbol namespace check
####################################################################

check-aliasing: ## Fail if the strict-aliasing warning is not actually armed
# CFLAGS names -fstrict-aliasing and -Wstrict-aliasing=1, and neither spelling
# tells you the level that results. -Wall sets the level to 3 on its own, an
# explicit level beats it from either side, and a later explicit level beats
# that - so the resolved level depends on the whole command line, and
# $(EXTRA_CFLAGS) sits at the end of it. `make EXTRA_CFLAGS=-Wstrict-aliasing=3`
# builds this library with the aliasing optimisation armed and the warning
# silent, every flag still present and every comment about them still true.
# The CFLAGS comment has the measured precedence table.
#
# So ask the compiler instead of the flag list: compile a violation with the
# real $(CFLAGS) and require the diagnostic. That reads the level the command
# line resolves to, which no review of the spelling can do. The design is the
# chron session's.
#
# The probe pins the level at exactly 1. Measured on it: level 1 reports it,
# and levels 0, 2 and 3 are all silent.
#
# ---- Do not simplify the probe. Its shape is what makes it discriminating.
#
# Diagnostics at -O2, counted across five violation shapes:
#
#                                                      L0  L1  L2  L3
#   cast of a pointer PARAMETER      <- this probe       0   1   0   0
#   struct-to-struct cast of a parameter                 0   1   0   0
#   a void * stored through a typed lvalue               0   1   1   0
#   *(int *)&local, *(long *)&s->member                  0   2   2   2
#   laundered through a `void * v = p` variable          0   0   0   0
#
# Written the obvious way, `*(int *)&local`, this gate would pass with the
# warning at level 3 and certify nothing - row four is reported at every
# level from 1 up. A later tidy-up that "simplifies" the probe therefore
# silently removes the only thing it measures. The chron session hit this as
# a live near-miss in their own control. Measured here rather than argued:
# with the probe rewritten as `*(int *)&l`, `make
# EXTRA_CFLAGS=-Wstrict-aliasing=3 check-aliasing` exits 0 - the one case the
# gate exists to catch, passing green.
#
# Two axes decide those rows, and they matter if this library ever moves off
# level 1. Isolated pairwise at -O2:
#
#                                              L0  L1  L2  L3
#   *(int *)&g          known object, direct    0   1   1   1
#   int * p = (int *)&g known object, via var   0   1   1   0
#   *(int *)d           PARAMETER, direct       0   1   0   0
#   int * p = (int *)d  parameter, via var      0   1   0   0   <- this probe
#
# Taking the address of an object the compiler can see is what level 2 needs;
# routing the cast through a separate pointer variable is what defeats level
# 3. It is not about storage class - a local is a known object too.
#
# So this probe certifies level 1 and **would be vacuous at level 2**: green,
# asserting nothing. A gate meant to certify "1 or 2, but not 3" needs the
# second row - a known object through a variable. The first row is no use as a
# probe at all, since it fires at every level from 1 up. Change the probe if
# the level ever changes, or the gate silently stops measuring. Axes isolated
# by the chron and image sessions, reproduced here.
#
# Two further limits bound what a green run may be said to mean.
# Level 3 is not blind in general - it catches row four - so this library's
# seven-of-nine sibling libraries sitting at 3 are not uninstrumented, they
# are blind to rows one to three. Row three is the shape obj_load.c actually
# had, eleven times. And nothing catches row five at any level, including 1:
# a clean run here is not evidence about punning laundered through a void *
# variable, which is the spelling real code reaches for most readily.
# Enumerated by the chron session, reproduced here.
#
# So a silent probe has three different causes and they want opposite fixes,
# which is why the failure branch *measures* the cause rather than naming the
# likeliest one. A gate whose diagnosis is one step off sends the next reader
# after something that is not wrong, and they will trust it because the gate
# was right to fire - chron's earlier version blamed a regression that had not
# happened, and this one's first version told a clang user their level was
# wrong when it was 1 and correct:
#
#   $(CC) reports no level at all   a compiler that accepts the option and
#                                   implements nothing. clang does this, so
#                                   under clang there is no instrument here -
#                                   and no sanitizer covers the class either.
#   $(CC) reports 0, 2 or 3         the level is wrong; the flags are present.
#                                   3 is also what -Wall implies, so it is an
#                                   override or a removal and this cannot say
#                                   which - it says so rather than guessing.
#   $(CC) reports 1                 the level is right and it still did not
#                                   fire, which nothing here explains. Suspect
#                                   the probe or the compiler, not CFLAGS.
#
# Reading the level needs its own guard: an empty answer is not a level. clang
# exits 1 and prints nothing, and a flag string gcc rejects produces the same
# empty output from a zero-length variable - so the exit status and a
# non-empty level are both checked before the number is believed. That trap
# is the chron session's, hit twice in one hour from opposite directions.
#
# The clean file is the control and it does two jobs. It must compile *and* be
# silent: if both files failed for an unrelated reason - a bad -I, a missing
# header - the probe's grep would find nothing, and a gate that only asked
# "no diagnostic on the clean one" would pass while measuring nothing.
	@mkdir -p $(BUILD_DIR)
	@printf 'int ghttp_alias_probe(float * f);\nint ghttp_alias_probe(float * f) { int * i = (int *)f; *i = 7; return *i; }\n' > $(BUILD_DIR)/alias_probe.c
	@printf 'int ghttp_alias_clean(int * i);\nint ghttp_alias_clean(int * i) { *i = 7; return *i; }\n' > $(BUILD_DIR)/alias_clean.c
	@probe=$$($(CC) $(CFLAGS) -Wno-error -c $(BUILD_DIR)/alias_probe.c -o $(BUILD_DIR)/alias_probe.o 2>&1); \
	ctl=$$($(CC) $(CFLAGS) -Wno-error -c $(BUILD_DIR)/alias_clean.c -o $(BUILD_DIR)/alias_clean.o 2>&1); ctlrc=$$?; \
	if [ $$ctlrc -ne 0 ]; then \
		printf '\033[0;31mcheck-aliasing: the control file did not compile, so this gate is measuring nothing:\033[0m\n%s\n' "$$ctl" >&2; \
		exit 1; \
	fi; \
	if printf '%s' "$$ctl" | grep -q 'strict-aliasing'; then \
		printf '\033[0;31mcheck-aliasing: the control file drew a strict-aliasing diagnostic, so the probe proves nothing:\033[0m\n%s\n' "$$ctl" >&2; \
		exit 1; \
	fi; \
	if printf '%s' "$$probe" | grep -q 'strict-aliasing'; then \
		printf 'check-aliasing: the planted violation is reported; the warning is armed at the level CFLAGS resolves to\n'; \
		exit 0; \
	fi; \
	qout=$$($(CC) -Q --help=warnings $(CFLAGS) 2>/dev/null); qrc=$$?; \
	level=$$(printf '%s' "$$qout" | awk '/-Wstrict-aliasing=</{print $$2}'); \
	if [ $$qrc -ne 0 ] || [ -z "$$level" ]; then \
		printf '\033[0;31mcheck-aliasing: the planted violation drew no diagnostic, and $(CC) reports no -Wstrict-aliasing level at all. That is a compiler which accepts the option and implements nothing - clang does exactly this - so the flags are intact and there is no aliasing instrument behind them. No sanitizer covers this class at any -O, so under this compiler the library has none.\033[0m\n' >&2; \
	elif [ "$$level" = 1 ]; then \
		printf '\033[0;31mcheck-aliasing: $(CC) reports -Wstrict-aliasing=1 and the planted violation still drew no diagnostic. The level is right and the warning did not fire, which neither the flags nor the level explains - suspect the probe or the compiler version before touching CFLAGS.\033[0m\n' >&2; \
	else \
		printf '\033[0;31mcheck-aliasing: CFLAGS resolves to -Wstrict-aliasing=%s, and only level 1 reports the planted store - 0, 2 and 3 are all silent on it. The level is wrong; the flags are not missing. Note that 3 is also what -Wall implies, so it means either an explicit override later on the command line or ALIASING flags that stopped being passed, and this cannot tell which.\033[0m\n' "$$level" >&2; \
	fi; \
	exit 1
check-symbols: ## Fail if any exported symbol lacks the version namespace
check-symbols: $(APP_DIR)/$(TARGET)
ifeq ($(OS_NAME), Linux)
	@leaked=$$(nm -D --defined-only $(APP_DIR)/$(TARGET) \
		| awk '$$2 ~ /^[TDBR]$$/ {print $$3}' \
		| grep -v '^$(LIBVER_SYMBOL)_' | grep -v '^_' || true); \
	if [ -n "$$leaked" ]; then \
		printf "\033[0;31m\n### Exported symbols missing the $(LIBVER_SYMBOL)_ namespace ###\033[0m\n" >&2; \
		printf "%s\n" "$$leaked" >&2; \
		printf "\nEach needs a '#define <name> GHOTIIO_HTTP(<name>)' line in namespace.h.\n" >&2; \
		printf "See CONVENTIONS.md section 4.\n" >&2; \
		exit 1; \
	fi
	@unexported=$$(find include -name '*.h' -exec awk '/^#if DOXYGEN/{d=1} d==0 && /^[a-z_][A-Za-z0-9_ ]*\**[[:space:]]*ghttp_[a-z0-9_]+[[:space:]]*\(/{print FILENAME": "$$0} /^#endif/{d=0}' {} + \
		| grep -vE 'typedef|static inline' || true); \
	if [ -n "$$unexported" ]; then \
		printf "\033[0;31m\n### Public declarations without GHTTP_API ###\033[0m\n" >&2; \
		printf "%s\n" "$$unexported" >&2; \
		printf "\nThese are hidden in the shared library. The tests link the archive and\n" >&2; \
		printf "would not notice; a consumer gets an undefined reference.\n" >&2; \
		exit 1; \
	fi
	@split=$$(nm -D --undefined-only $(APP_DIR)/$(TARGET) \
		| awk '{print $$2}' | grep '^$(LIBVER_SYMBOL)_' || true); \
	if [ -n "$$split" ]; then \
		printf "\033[0;31m\n### Renamed but undefined - a split symbol ###\033[0m\n" >&2; \
		printf "%s\n" "$$split" >&2; \
		printf "\nA translation unit referenced the namespaced name while the one that\n" >&2; \
		printf "defines it did not see the rename - usually an internal header that\n" >&2; \
		printf "declares or defines something without including macros.h first.\n" >&2; \
		exit 1; \
	fi
	@nomacros=$$(find include src -name '*.h' \
		! -name 'libver.h' ! -name 'libver_gen.h' ! -name 'namespace.h' ! -name 'macros.h' \
		-exec grep -L '#include <ghoti.io/http/macros.h>' {} + || true); \
	if [ -n "$$nomacros" ]; then \
		printf "\033[0;31m\n### Headers that do not include macros.h ###\033[0m\n" >&2; \
		printf "%s\n" "$$nomacros" >&2; \
		printf "\nEvery header must include <ghoti.io/http/macros.h> before it declares\n" >&2; \
		printf "anything, so that the renames in namespace.h are already in effect. A\n" >&2; \
		printf "header that skips it can name a type before that type has been renamed,\n" >&2; \
		printf "producing two different types under one spelling.\n" >&2; \
		printf "See CONVENTIONS.md section 4.\n" >&2; \
		exit 1; \
	fi
	@badguards=$$(find include src -name '*.h' -exec awk 'FNR==1{d=0} !d && /^#ifndef/{print $$2; d=1}' {} + \
		| awk '$$1 !~ /^GHOTI_IO_GHTTP_/ {print $$1}' || true); \
	if [ -n "$$badguards" ]; then \
		printf "\033[0;31m\n### Include guards with the wrong prefix ###\033[0m\n" >&2; \
		printf "%s\n" "$$badguards" >&2; \
		printf "\nGuards mirror the path: GHOTI_IO_GHTTP_<PATH>_H. A guard without the\n" >&2; \
		printf "library token is one rename away from colliding with another library's.\n" >&2; \
		exit 1; \
	fi
	@dupguards=$$(find include src -name '*.h' -exec awk 'FNR==1{d=0} !d && /^#ifndef/{print $$2; d=1}' {} + \
		| sort | uniq -d || true); \
	if [ -n "$$dupguards" ]; then \
		printf "\033[0;31m\n### Headers sharing an include guard ###\033[0m\n" >&2; \
		printf "%s\n" "$$dupguards" >&2; \
		printf "\nTwo headers with one guard means whichever is included second is\n" >&2; \
		printf "silently empty. Guards mirror the path: GHOTI_IO_GHTTP_<PATH>_H.\n" >&2; \
		exit 1; \
	fi
	@printf "\033[0;32mEvery exported symbol carries the $(LIBVER_SYMBOL)_ namespace.\033[0m\n"
	@printf "\033[0;32mEvery public declaration carries GHTTP_API.\033[0m\n"
	@printf "\033[0;32mEvery header includes macros.h.\033[0m\n"
	@printf "\033[0;32mEvery include guard is unique and correctly prefixed.\033[0m\n"
else
	@printf "check-symbols: skipped (Linux only)\n"
endif

check-defects: ## Fail unless the unit tests catch each planted defect
check-defects:
# Not a prerequisite of anything it needs: it copies the tree and builds the
# copies itself, so it works on a tree nobody has built.
	@tools/check-defects.sh "$(MAKE)" "$(BUILD_DIR)" $(if $(PREFIX),PREFIX=$(PREFIX)) CUTIL_PC=$(CUTIL_PC)

test: ## Make and run the unit tests
test: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES) $(TEST_GATES)
# `|| exit 1` is what makes this a gate at all. Without it the loop ran every
# binary and discarded every exit status, so `make test` returned 0 whatever
# happened - a failing assertion, a segfault, a sanitizer abort. The failure
# was visible only as "[  FAILED  ]" text in the log, which meant anything
# scoring this target had to read the log, and a crash prints no such line at
# all. Measured before the fix: a deliberate EXPECT_EQ(1, 2) gave exit 0, and
# so did a null dereference. test-asan already had this; test and
# test-valgrind did not.
	@for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		printf "\033[0;30;43m\n"; \
		printf "############################\n"; \
		printf "### Running %s tests ###\n" "$$test_name"; \
		printf "############################"; \
		printf "\033[0m\n\n"; \
		LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$test_exe --gtest_brief=1 || exit 1; \
	done

test-quiet: ## Run tests with minimal output (one line per test suite)
test-quiet: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES)
	@total_tests=0; total_passed=0; total_failed=0; total_time=0; failed_suites=""; \
	printf "\n\033[1;36m%-30s %8s %10s %s\033[0m\n" "Test Suite" "Tests" "Time" "Status"; \
	printf "\033[1;36m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		output=$$(LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$test_exe --gtest_brief=1 2>&1); \
		exit_code=$$?; \
		num_tests=$$(echo "$$output" | grep -oP '\[\s*=+\s*\]\s*\K\d+(?=\s+tests?)' | head -1); \
		time_ms=$$(echo "$$output" | grep -oP '\(\K\d+(?=\s*ms\s*total\))' | head -1); \
		[ -z "$$num_tests" ] && num_tests=0; \
		[ -z "$$time_ms" ] && time_ms=0; \
		total_tests=$$((total_tests + num_tests)); \
		total_time=$$((total_time + time_ms)); \
		if [ $$exit_code -eq 0 ]; then \
			total_passed=$$((total_passed + num_tests)); \
			printf "%-30s %8d %8dms \033[0;32mPASS\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms"; \
		else \
			failures=$$(echo "$$output" | grep -oP '\[\s*FAILED\s*\]\s*\K\d+' | head -1); \
			[ -z "$$failures" ] && failures=$$num_tests; \
			total_failed=$$((total_failed + failures)); \
			total_passed=$$((total_passed + num_tests - failures)); \
			printf "%-30s %8d %8dms \033[0;31mFAIL\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms"; \
			failed_suites="$$failed_suites\n\033[0;31m=== $$test_name FAILURES ===\033[0m\n$$output\n"; \
		fi; \
	done; \
	printf "\033[1;36m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	if [ $$total_failed -eq 0 ]; then \
		printf "\033[0;32m%-30s %8d %6dms PASS\033[0m\n\n" "TOTAL" "$$total_tests" "$$total_time"; \
	else \
		printf "\033[0;31m%-30s %8d %6dms FAIL (%d failed)\033[0m\n" "TOTAL" "$$total_tests" "$$total_time" "$$total_failed"; \
		printf "$$failed_suites\n"; \
		exit 1; \
	fi

test-valgrind: ## Run all tests under valgrind (Linux only)
test-valgrind: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES)
# VALGRIND_FLAGS carries --error-exitcode=1, so valgrind reports a leak or an
# invalid access in its status - and the loop used to discard it, along with
# the test binary's own. See the note on `test`.
ifeq ($(OS_NAME), Linux)
	@for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		printf "\033[0;30;43m\n"; \
		printf "############################\n"; \
		printf "### Running %s tests under Valgrind ###\n" "$$test_name"; \
		printf "############################"; \
		printf "\033[0m\n\n"; \
		LD_LIBRARY_PATH="$(TEST_LD_PATH)" valgrind $(VALGRIND_FLAGS) $$test_exe --gtest_brief=1 || exit 1; \
	done
else
	@printf "\033[0;31m\nValgrind is only available on Linux\n\033[0m\n"
	@exit 1
endif

# test-valgrind-quiet passes only when both the tests pass and Valgrind is
# clean, so a FAIL here can mean an assertion failure even with no leaks.
test-valgrind-quiet: ## Run tests under valgrind with minimal output (Linux only)
test-valgrind-quiet: $(APP_DIR)/$(TARGET) $(TEST_EXECUTABLES)
ifeq ($(OS_NAME), Linux)
	@total_tests=0; total_failed=0; total_time=0; failed_suites=""; \
	printf "\n\033[1;35m%-30s %8s %10s %s\033[0m\n" "Test Suite (Valgrind)" "Tests" "Time" "Status"; \
	printf "\033[1;35m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	for test_exe in $(TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		output=$$(LD_LIBRARY_PATH="$(TEST_LD_PATH)" valgrind $(VALGRIND_FLAGS) $$test_exe --gtest_brief=1 2>&1); \
		exit_code=$$?; \
		num_tests=$$(echo "$$output" | grep -oP '\[\s*=+\s*\]\s*\K\d+(?=\s+tests?)' | head -1); \
		time_ms=$$(echo "$$output" | grep -oP '\(\K\d+(?=\s*ms\s*total\))' | head -1); \
		[ -z "$$num_tests" ] && num_tests=0; \
		[ -z "$$time_ms" ] && time_ms=0; \
		total_tests=$$((total_tests + num_tests)); \
		total_time=$$((total_time + time_ms)); \
		has_leak=$$(echo "$$output" | grep -c "are definitely lost\|are indirectly lost\|are possibly lost" || true); \
		if [ $$exit_code -eq 0 ] && [ $$has_leak -eq 0 ]; then \
			printf "%-30s %8d %8dms \033[0;32mPASS\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms"; \
		else \
			if [ $$has_leak -gt 0 ]; then status_msg="LEAK"; else status_msg="FAIL"; fi; \
			total_failed=$$((total_failed + 1)); \
			printf "%-30s %8d %8dms \033[0;31m%s\033[0m\n" "$$test_name" "$$num_tests" "$$time_ms" "$$status_msg"; \
			failed_suites="$$failed_suites\n\033[0;31m=== $$test_name FAILURES ===\033[0m\n$$output\n"; \
		fi; \
	done; \
	printf "\033[1;35m%-30s %8s %10s %s\033[0m\n" "------------------------------" "--------" "----------" "------"; \
	if [ $$total_failed -eq 0 ]; then \
		printf "\033[0;32m%-30s %8d %6dms PASS\033[0m\n\n" "TOTAL" "$$total_tests" "$$total_time"; \
	else \
		printf "\033[0;31m%-30s %8d %6dms FAIL (%d suites)\033[0m\n" "TOTAL" "$$total_tests" "$$total_time" "$$total_failed"; \
		printf "$$failed_suites\n"; \
		exit 1; \
	fi
else
	@printf "\033[0;31m\nValgrind is only available on Linux\n\033[0m\n"
	@exit 1
endif

####################################################################
# Sanitizer build (ASan + UBSan): separate build dir, run the test suite
####################################################################
# -fno-sanitize-recover: without it UBSan PRINTS a diagnostic and carries on,
# so the process still exits 0 and the suite reports clean over undefined
# behaviour it just described. A gate that cannot fail is not a gate.
#
# float-cast-overflow is named separately because GCC does NOT put it in the
# `undefined` group - and so `-fno-sanitize-recover=undefined` does not reach
# it either. Measured: a cast of 1e30 to int under `-fsanitize=undefined
# -fno-sanitize-recover=undefined` printed nothing and exited 0, and with this
# flag it reports. Converting a float that does not fit is undefined
# behaviour, this library does it wherever a numeric option lands in an
# integer field, and neither half of the gate was watching. The same reasoning
# does not extend to float-divide-by-zero, which IEEE defines.
UBSAN_CHECKS := undefined,float-cast-overflow
# The gate's own -O, pinned rather than inherited, so the sanitizer tree does
# not move when the release level does and shares FUZZ_SAN's codegen. Nothing
# a sanitizer can see depends on the level (model's Makefile has the table);
# no sanitizer reports a strict-aliasing violation at any level, which is why
# check-aliasing exists.
ASAN_UBSAN_FLAGS := -fsanitize=address,$(UBSAN_CHECKS) -fno-sanitize-recover=$(UBSAN_CHECKS) -fno-omit-frame-pointer -g -O1
# The instrumented-coverage tree, kept apart from the release objects for the
# same reason the sanitizer ones are: a plain `make` must never be able to
# find an object built with flags it did not ask for.
COV_BUILD_DIR := ./build/$(BUILD)-cov

ASAN_BUILD_DIR := ./build/$(BUILD)-asan
ASAN_OBJ_DIR := $(ASAN_BUILD_DIR)/objects
ASAN_FLAGS_STAMP := $(ASAN_OBJ_DIR)/.flags
ASAN_APP_DIR := $(ASAN_BUILD_DIR)/apps

ASAN_LIBOBJECTS := $(patsubst src/%.c,$(ASAN_OBJ_DIR)/%.o,$(SOURCES))

# The ASan tree needs header dependencies as much as the release tree does,
# and did not have them. Adding a field to GHTTP_Limits and running `make
# test-asan` reported "AddressSanitizer: unknown-crash ... in
# ghttp_limits_default": a struct written by new code into a buffer sized by
# old code, from objects that no longer matched the header. A clean rebuild
# passed. That is worse than a stale result, because the report names a
# source line and accuses working code.
#
# This sits HERE, after ASAN_LIBOBJECTS, and not with the release DEPFILES
# near the top. `:=` expands immediately, so up there ASAN_LIBOBJECTS is
# still empty and the list came out blank - which looks exactly like a
# working fix, since a no-op build is 0 either way. What tells them apart is
# editing a header and counting: 0 before, and every dependent object after.
ASAN_DEPFILES := $(ASAN_LIBOBJECTS:.o=.d) \
    $(foreach pair,$(TEST_PAIRS),$(ASAN_OBJ_DIR)/tests/$(basename $(notdir $(word 1,$(subst |, ,$(pair))))).d)
-include $(ASAN_DEPFILES)
ASAN_TARGET := $(BASE_NAME_PREFIX)-asan.$(LIB_EXTENSION)
ASAN_HTTPLIBRARY := -L $(ASAN_APP_DIR) -l$(SUITE)-$(PROJECT)$(BRANCH)-asan

ASAN_CFLAGS := $(CFLAGS) $(ASAN_UBSAN_FLAGS) -DGHTTP_BUILD -DGHTTP_TEST_BUILD
ASAN_CXXFLAGS := $(CXXFLAGS) $(ASAN_UBSAN_FLAGS)
ASAN_LDFLAGS := $(LDFLAGS) $(ASAN_UBSAN_FLAGS)
ifeq ($(UNAME_S), Linux)
	ASAN_CFLAGS += -fPIC
endif

$(ASAN_OBJ_DIR)/%.o: src/%.c $(ASAN_FLAGS_STAMP) | $(LIBVER_GEN)
	@printf "\n### Compiling (ASan+UBSan): $< ###\n"
	@mkdir -p $(@D)
	$(CC) $(ASAN_CFLAGS) $(INCLUDE) -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(ASAN_APP_DIR)/$(ASAN_TARGET): $(ASAN_LIBOBJECTS)
	@printf "\n### Linking ASan+UBSan HTTP Library ###\n"
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) -shared -o $@ $^ $(ASAN_LDFLAGS) $(CUTIL_LIBS)

$(ASAN_OBJ_DIR)/tests/%.o: tests/%.cpp $(ASAN_FLAGS_STAMP) | $(LIBVER_GEN)
	@printf "\n### Compiling ASan Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) $(INCLUDE) -Itests -c $< -MMD -MP -MF $(@:.o=.d) -o $@

$(ASAN_OBJ_DIR)/tests/%.o: tests/unit/%.cpp $(ASAN_FLAGS_STAMP) | $(LIBVER_GEN)
	@printf "\n### Compiling ASan Test: $* ###\n"
	@mkdir -p $(@D)
	$(CXX) $(ASAN_CXXFLAGS) $(INCLUDE) -Itests -c $< -MMD -MP -MF $(@:.o=.d) -o $@

define asan-test-executable-rule
ASAN_TEST_OBJ_$1 := $(ASAN_OBJ_DIR)/tests/$(basename $(notdir $1)).o

$(ASAN_APP_DIR)/$2$(EXE_EXTENSION): $$(ASAN_TEST_OBJ_$1) $(ASAN_APP_DIR)/$(ASAN_TARGET)
	@printf "\n### Linking ASan Test: $2 ###\n"
	@mkdir -p $$(@D)
	$(CXX) $(ASAN_CXXFLAGS) -o $$@ $$(ASAN_TEST_OBJ_$1) $(ASAN_LDFLAGS) $(ASAN_HTTPLIBRARY) $(CUTIL_LIBS) $(TESTFLAGS)
endef

$(foreach pair,$(TEST_PAIRS),\
	$(eval $(call asan-test-executable-rule,$(word 1,$(subst |, ,$(pair))),$(word 2,$(subst |, ,$(pair))))))

ASAN_TEST_EXECUTABLES := $(addprefix $(ASAN_APP_DIR)/,$(addsuffix $(EXE_EXTENSION),$(TEST_NAMES)))

# ASan insists on being the first library loaded. A desktop session that sets
# LD_PRELOAD for its own reasons (libgtk3-nocsd, for instance) puts something
# ahead of it and every sanitized binary refuses to start, so put the runtime
# back in front rather than discarding whatever the user had set.
ASAN_RUNTIME := $(shell $(CC) -print-file-name=libasan.so 2>/dev/null)

test-asan: ## Build with ASan+UBSan and run the test suite
test-asan: $(ASAN_TEST_EXECUTABLES)
	@for test_exe in $(ASAN_TEST_EXECUTABLES); do \
		test_name=$$(basename $$test_exe $(EXE_EXTENSION)); \
		printf "\033[0;30;43m\n### Running %s (ASan+UBSan) ###\033[0m\n\n" "$$test_name"; \
		LD_PRELOAD="$(ASAN_RUNTIME)$${LD_PRELOAD:+:$$LD_PRELOAD}" \
		LD_LIBRARY_PATH="$(ASAN_APP_DIR):$(LIB_INSTALL_PATH)/$(SUITE)" \
			$$test_exe --gtest_brief=1 || exit 1; \
	done
	@printf "\033[0;32m\nASan+UBSan suite clean.\033[0m\n"

####################################################################
# Fuzzing (libFuzzer)
####################################################################
#
# The library is rebuilt with -fsanitize=fuzzer-no-link rather than linking the
# ordinary shared library. That matters: libFuzzer steers its mutations by the
# coverage it observes, and a harness linked against an uninstrumented library
# sees none of the parser's branches, which leaves it generating random input
# rather than exploring the format.
FUZZ_CC ?= clang
FUZZ_CXX ?= clang++
FUZZ_CC_OK := $(shell which $(FUZZ_CC) 2>/dev/null)
# -fstrict-aliasing is named so that the fuzz tree's aliasing assumption is
# stated rather than inherited from the fuzzing compiler's default (model's
# Makefile has the measurement). This line carries -w, so the fuzz tree is not
# a warning gate.
FUZZ_SAN := -fsanitize=address,$(UBSAN_CHECKS) -fno-omit-frame-pointer -g -O1 -fstrict-aliasing
FUZZ_LIB_FLAGS := $(FUZZ_SAN) -fsanitize=fuzzer-no-link
FUZZ_BIN_FLAGS := $(FUZZ_SAN) -fsanitize=fuzzer
FUZZ_DIR := $(BUILD_DIR)/fuzz
FUZZ_OBJ_DIR := $(FUZZ_DIR)/objects
FUZZ_FLAGS_STAMP := $(FUZZ_OBJ_DIR)/.flags
FUZZ_APP_DIR := $(FUZZ_DIR)/apps
FUZZ_OBJECTS := $(patsubst src/%.c,$(FUZZ_OBJ_DIR)/%.o,$(SOURCES))
FUZZ_CORPUS := tests/fuzz/corpus

# A smoke-test length by default; for a real campaign: make fuzz FUZZ_TIME=3600
FUZZ_TIME ?= 60

$(FUZZ_OBJ_DIR)/%.o: src/%.c $(FUZZ_FLAGS_STAMP) | $(LIBVER_GEN)
	@mkdir -p $(@D)
	@$(FUZZ_CC) $(FUZZ_LIB_FLAGS) -std=c17 -w $(INCLUDE) -c $< -o $@

# $1 = harness basename (fuzz_obj), $2 = target suffix (obj)
define fuzz-rule
fuzz-$2: ## Build the $2 fuzz harness (requires clang)
fuzz-$2: $$(FUZZ_APP_DIR)/$1

$$(FUZZ_APP_DIR)/$1: tests/fuzz/$1.cpp $$(FUZZ_OBJECTS) $$(FUZZ_FLAGS_STAMP)
	@if [ -z "$$(FUZZ_CC_OK)" ]; then \
		echo "fuzzing requires $$(FUZZ_CXX); install clang or set FUZZ_CC/FUZZ_CXX"; \
		exit 1; \
	fi
	@mkdir -p $$(@D) $$(FUZZ_CORPUS)/$2
	@printf "\n### Building fuzz harness: $1 ###\n"
	$$(FUZZ_CXX) $$(FUZZ_BIN_FLAGS) -std=c++20 -w $$(INCLUDE) \
		-o $$@ $$< $$(FUZZ_OBJECTS) $(CUTIL_LIBS)

fuzz-run-$2: ## Run the $2 fuzzer for $$(FUZZ_TIME) seconds
fuzz-run-$2: $$(FUZZ_APP_DIR)/$1
	@mkdir -p $$(FUZZ_CORPUS)/$2
	@printf "\n### Fuzzing $2 for $$(FUZZ_TIME)s ###\n"
	@LD_LIBRARY_PATH="$(TEST_LD_PATH)" $$(FUZZ_APP_DIR)/$1 $$(FUZZ_CORPUS)/$2 \
		-max_total_time=$$(FUZZ_TIME) -print_final_stats=1
endef

$(eval $(call fuzz-rule,fuzz_parse,parse))
$(eval $(call fuzz-rule,fuzz_roundtrip,roundtrip))

fuzz: ## Build and run every fuzzer for $(FUZZ_TIME) seconds each
fuzz: fuzz-run-parse fuzz-run-roundtrip

fuzz-clean: ## Remove the fuzz build (keeps the corpus)
	-@rm -rf $(FUZZ_DIR)

####################################################################
# Install / uninstall
####################################################################

# Where the loader configuration fragment is written. Kept overridable so a
# staged or user-prefix install has somewhere to write it.
LDCONF_INSTALL_PATH ?= /etc/ld.so.conf.d

# What goes in the .pc Requires: field. Built from the same variables the
# compile uses, so a dependency on another branch cannot be named one way for
# the build and another way for consumers.
PC_REQUIRES := $(CUTIL_PC)

# Where this project's own .pc file is installed.
PKGCONFIG_INSTALL_PATH ?= $(PC_INSTALL_PATH)


install: ## Install the library globally, requires sudo
# Depends on all: install used to copy whatever happened to be in the build
# directory, so it could install a stale artifact or fail outright on a clean
# tree.
install: all
	# Installing the shared library.
	@mkdir -p $(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Linux)
	@cp $(APP_DIR)/$(TARGET) $(LIB_INSTALL_PATH)/$(SUITE)/
	@ln -f -s $(TARGET) $(LIB_INSTALL_PATH)/$(SUITE)/$(SO_NAME)
	@ln -f -s $(SO_NAME) $(LIB_INSTALL_PATH)/$(SUITE)/$(BASE_NAME)
	# Installing the ld configuration file.
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then mkdir -p $(LDCONF_INSTALL_PATH); fi
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then echo "$(LIB_INSTALL_PATH)/$(SUITE)" > $(LDCONF_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).conf; fi
endif
ifeq ($(OS_NAME), Windows)
# The .dll goes in bin/, where the loader finds it once that directory is on
# PATH - Windows has no rpath. The import library goes where the .pc's -L
# points, lib/$(SUITE)/, as the .so does on Linux; in lib/ no -L named it.
	@mkdir -p $(BIN_INSTALL_PATH) $(LIB_INSTALL_PATH)/$(SUITE)
	@cp $(APP_DIR)/$(TARGET).a $(LIB_INSTALL_PATH)/$(SUITE)/
	@cp $(APP_DIR)/$(TARGET) $(BIN_INSTALL_PATH)/
endif
	# Installing the headers.
	# Removed first: this directory is owned entirely by this project and
	# branch, and copying over the top of it would leave headers behind that
	# have since been renamed or deleted.
	@rm -rf $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@mkdir -p $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@if [ -d include/ghoti.io ]; then \
		cp -r include/ghoti.io $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)/ ; \
	fi
	@if [ -d $(GEN_DIR)/ghoti.io ]; then \
		cp -r $(GEN_DIR)/ghoti.io $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)/ ; \
	fi
	# Installing the pkg-config files.
	@mkdir -p $(PKGCONFIG_INSTALL_PATH)
	@cat pkgconfig/$(SUITE)-$(PROJECT).pc | sed 's/(SUITE)/$(SUITE)/g; s/(PROJECT)/$(PROJECT)/g; s/(BRANCH)/$(BRANCH)/g; s/(VERSION)/$(VERSION)/g; s|(PC_LIB_DIR)|$(PC_LIB_DIR)|g; s|(PC_INCLUDE_DIR)|$(PC_INCLUDE_DIR)|g; s|(REQUIRES)|$(PC_REQUIRES)|g' > $(PKGCONFIG_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).pc
ifeq ($(OS_NAME), Linux)
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then ldconfig >> /dev/null 2>&1; fi
endif
	@echo "Ghoti.io $(PROJECT)$(BRANCH) installed"

uninstall: ## Delete the globally-installed files.  Requires sudo.
ifeq ($(OS_NAME), Linux)
	@rm -f $(LIB_INSTALL_PATH)/$(SUITE)/$(BASE_NAME)*
	@rm -f $(LDCONF_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).conf
endif
ifeq ($(OS_NAME), Windows)
	@rm -f $(LIB_INSTALL_PATH)/$(SUITE)/$(TARGET).a
	@rm -f $(BIN_INSTALL_PATH)/$(TARGET)
endif
	@rm -rf $(INCLUDE_INSTALL_PATH)/$(SUITE)/$(PROJECT)$(BRANCH)
	@rm -f $(PKGCONFIG_INSTALL_PATH)/$(SUITE)-$(PROJECT)$(BRANCH).pc
	@rmdir --ignore-fail-on-non-empty $(INCLUDE_INSTALL_PATH)/$(SUITE)
	@rmdir --ignore-fail-on-non-empty $(LIB_INSTALL_PATH)/$(SUITE)
ifeq ($(OS_NAME), Linux)
	@if [ -n "$(LDCONF_INSTALL_PATH)" ]; then ldconfig >> /dev/null 2>&1; fi
endif
	@echo "Ghoti.io $(PROJECT)$(BRANCH) has been uninstalled"

debug: ## Build the project in DEBUG mode
	make all BUILD=debug

install-debug: ## Install the DEBUG library globally, requires sudo
	make install BUILD=debug

uninstall-debug: ## Delete the DEBUG globally-installed files.  Requires sudo.
	make uninstall BUILD=debug

test-debug: ## Make and run the Unit tests in DEBUG mode
	make test BUILD=debug

test-valgrind-debug: ## Run all tests under valgrind in DEBUG mode (Linux only)
	make test-valgrind BUILD=debug

watch-debug: ## Watch the file directory for changes and compile the target in DEBUG mode
	make watch BUILD=debug

test-watch-debug: ## Watch the file directory for changes and run the unit tests in DEBUG mode
	make test-watch BUILD=debug

docs: ## Generate the documentation in the ./docs subdirectory
	doxygen

docs-pdf: docs ## Generate the documentation as a pdf, at ./docs/(SUITE)-(PROJECT)(BRANCH).pdf
	cd ./docs/latex/ && make
	mv -f ./docs/latex/refman.pdf ./docs/$(SUITE)-$(PROJECT)$(BRANCH)-docs.pdf

cloc: ## Count the lines of code used in the project
	cloc src include tests Makefile

coverage: ## Build instrumented, run the tests, and report line coverage
# The instrumented build has a tree of its own, the way the sanitizer builds
# do, and that is the whole of the safety here. It used to share the ordinary
# object tree and clean before and after, which works right up until somebody
# runs the instrumented build by hand instead of through this target.
#
# What happens then is worth spelling out, because the obvious check says the
# tree is fine. The --coverage objects stay behind carrying undefined
# __gcov_* references, but the .so built alongside them was linked WITH
# --coverage, so it resolves them and `nm -D --undefined-only` reports it
# clean. Nothing looks wrong. The contamination is latent in the objects: a
# later plain `make` finds them newer than their sources, does not rebuild
# them, and the first time it has any reason to RELINK it produces a .so with
# three undefined gcov symbols. bootstrap.sh installs that, and every
# downstream library fails to link.
#
# That happened. It broke the shared prefix for the whole workspace and was
# found by a sibling project failing to link, not by anything here - measured
# afterwards: instrumented object 3 gcov refs, the .so beside it 0, the same
# .so after a relink 3.
#
# So this is no longer a rule to remember. The release tree is not touched at
# all, there is nothing to clean up afterwards, and the hand-rolled shortcut
# that caused it - wanting the .gcov files, which this target used to destroy
# on its way out - no longer needs taking.
#
# The .gcda counters are removed first rather than the objects: gcov merges
# profiles across runs, so a stale one from a previous source revision reports
# against lines that have moved. The objects themselves are make's business.
	@rm -rf $(COV_BUILD_DIR)/objects/*.gcda \
		$(COV_BUILD_DIR)/objects/*/*.gcda 2> /dev/null || true
# TEST_GATES is cleared because --coverage links the gcov runtime, which
# exports mangle_path. check-symbols is right to reject that in a shipping
# build and wrong to reject it here, and it made this target fail before it
# ever produced a report.
	@status=0; \
	$(MAKE) --no-print-directory test TEST_GATES= \
		BUILD_DIR=$(COV_BUILD_DIR) \
		EXTRA_CFLAGS="--coverage -O0" \
		EXTRA_LDFLAGS="--coverage" > /dev/null || status=$$?; \
	if [ $$status -eq 0 ]; then \
		tools/coverage.sh $(COV_BUILD_DIR)/objects || status=$$?; \
	else \
		printf "coverage: the instrumented test run failed; no report\n" >&2; \
	fi; \
	exit $$status

clean: ## Remove all contents of the build directories.
	-@rm -rvf $(COV_BUILD_DIR)
	-@rm -rvf $(OBJ_DIR)/*
	-@rm -rvf $(APP_DIR)/*
	-@rm -rvf $(GEN_DIR)/*
	-@rm -rvf $(ASAN_BUILD_DIR)

help: ## Display this help
	@grep -E '^[ a-zA-Z_-]+:.*?## .*$$' Makefile | sort | sed 's/\\([^:]*\\):.*## \\(.*\\)/\\1:\\2/' | awk -F: '{printf "%-20s %s\n", $$1, $$2}' | sed "s/(SUITE)/$(SUITE)/g; s/(PROJECT)/$(PROJECT)/g; s/(BRANCH)/$(BRANCH)/g"


####################################################################
# Flag stamps
####################################################################
# Each build tree carries the flag string it was built with. The stamp is
# rewritten only when that string differs -- written to a scratch file,
# compared, moved into place only on a difference -- so its mtime moves on a
# flag change and on nothing else. The object rules above depend on it.
#
# This replaces listing `Makefile` as a prerequisite, which was too broad (a
# comment-only edit recompiled everything) and too narrow (a command-line
# override such as `make EXTRA_CFLAGS=-O2` changes no file's mtime and so was
# invisible).
#
# These rules sit at the end of the file for two reasons. A rule's target
# expands when make reads the line, so a stamp rule above its own OBJ_DIR
# definition has an empty target: not an error, just a rule that silently does
# not exist. And the first target in a makefile is the default goal, so a stamp
# rule above `all:` makes a bare `make` build the stamp and nothing else.
# Each stamp must record the variables its own recipes expand, not the ones
# they are derived from. The release stamp recorded $(CFLAGS) while the
# library objects compile with $(LIB_CFLAGS); changing a flag that lives only
# in LIB_CFLAGS -- -fvisibility=hidden, -DGHTTP_BUILD -- moved no recorded
# string and rebuilt nothing. Measured before the fix: 0 compiles, where
# naming Makefile as a prerequisite had rebuilt all 10. That is strictly
# worse than having no stamp, because a rebuild that does not happen looks
# exactly like a build that was already current.
#
# The compiler belongs in the string too. `make CC=clang` is a command-line
# override that changes every object and no file's mtime, which is precisely
# the case these stamps exist for.
#
# The compiler and every flag a recipe expands are recorded; a recipe that
# expands a variable its stamp does not record is the defect to look for.
.PHONY: force-flags

$(FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CXX) $(LIB_CFLAGS) $(CFLAGS) $(CXXFLAGS) $(LDFLAGS) $(INCLUDE) $(HTTPLIBRARY) $(CUTIL_LIBS) $(TESTFLAGS) $(TEST_LDFLAGS) $(OS_SPECIFIC_LIBRARY_NAME_FLAG)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

$(ASAN_FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(CC) $(CXX) $(ASAN_CFLAGS) $(ASAN_CXXFLAGS) $(ASAN_LDFLAGS) $(INCLUDE) $(ASAN_HTTPLIBRARY) $(CUTIL_LIBS) $(TESTFLAGS)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

$(FUZZ_FLAGS_STAMP): force-flags
	@mkdir -p $(@D)
	@printf '%s\n' '$(FUZZ_CC) $(FUZZ_CXX) $(FUZZ_SAN) $(FUZZ_LIB_FLAGS) $(FUZZ_BIN_FLAGS) $(INCLUDE) $(CUTIL_LIBS)' > $@.new
	@cmp -s $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@
