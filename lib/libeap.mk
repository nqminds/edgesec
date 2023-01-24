# Based on https://w1.fi/cgit/hostap/tree/eap_example/Makefile and
# https://w1.fi/cgit/hostap/tree/hostapd/Makefile

alib = libeap.a
ALL = $(alib)
CONFIG_FILE = .config
INSTALL_DIR=$(CONFIG_LIBEAP_INSTALL_DIR)

include ../src/build.rules

CFLAGS += $(EXTRA_CFLAGS)
CFLAGS  += -fPIC -DPIC

CFLAGS += -I.
CFLAGS += -I$(abspath ../src)
CFLAGS += -I$(abspath ../src/utils)

export BINDIR ?= /usr/local/bin/

ifndef CONFIG_NO_GITVER
# Add VERSION_STR postfix for builds from a git repository
ifeq ($(wildcard ./.git),./.git)
GITVER := $(shell git describe --dirty=+)
ifneq ($(GITVER),)
CFLAGS += -DGIT_VERSION_STR_POSTFIX=\"-$(GITVER)\"
endif
endif
endif

ifdef CONFIG_TESTING_OPTIONS
CFLAGS += -DCONFIG_TESTING_OPTIONS
CONFIG_WPS_TESTING=y
endif

ifndef CONFIG_OS
ifdef CONFIG_NATIVE_WINDOWS
CONFIG_OS=win32
else
CONFIG_OS=unix
endif
endif

ifeq ($(CONFIG_OS), internal)
CFLAGS += -DOS_NO_C_LIB_DEFINES
endif

ifdef CONFIG_NATIVE_WINDOWS
CFLAGS += -DCONFIG_NATIVE_WINDOWS
LIBS += -lws2_32
endif

NEED_RC4=y
NEED_AES=y
NEED_MD5=y
NEED_SHA1=y

ifndef CONFIG_ELOOP
CONFIG_ELOOP=eloop
endif

ifeq ($(CONFIG_ELOOP), eloop)
# Using glibc < 2.17 requires -lrt for clock_gettime()
LIBS += -lrt
endif

ifdef CONFIG_ELOOP_POLL
CFLAGS += -DCONFIG_ELOOP_POLL
endif

ifdef CONFIG_ELOOP_EPOLL
CFLAGS += -DCONFIG_ELOOP_EPOLL
endif

ifdef CONFIG_ELOOP_KQUEUE
CFLAGS += -DCONFIG_ELOOP_KQUEUE
endif

ifdef CONFIG_CODE_COVERAGE
CFLAGS += -O0 -fprofile-arcs -ftest-coverage
LIBS += -lgcov
endif

ifdef CONFIG_ERP
CFLAGS += -DCONFIG_ERP
NEED_HMAC_SHA256_KDF=y
endif

ifdef CONFIG_EAP_MD5
CFLAGS += -DEAP_SERVER_MD5
OBJS += ../src/eap_server/eap_server_md5.o
CHAP=y
endif

ifdef CONFIG_EAP_TLS
CFLAGS += -DEAP_SERVER_TLS
OBJS += ../src/eap_server/eap_server_tls.o
TLS_FUNCS=y
endif

ifdef CONFIG_EAP_UNAUTH_TLS
CFLAGS += -DEAP_SERVER_UNAUTH_TLS
ifndef CONFIG_EAP_TLS
OBJS += ../src/eap_server/eap_server_tls.o
TLS_FUNCS=y
endif
endif

ifdef CONFIG_EAP_PEAP
CFLAGS += -DEAP_SERVER_PEAP
OBJS += ../src/eap_server/eap_server_peap.o
OBJS += ../src/eap_common/eap_peap_common.o
TLS_FUNCS=y
CONFIG_EAP_MSCHAPV2=y
endif

ifdef CONFIG_EAP_TTLS
CFLAGS += -DEAP_SERVER_TTLS
OBJS += ../src/eap_server/eap_server_ttls.o
TLS_FUNCS=y
CHAP=y
endif

ifdef CONFIG_EAP_MSCHAPV2
CFLAGS += -DEAP_SERVER_MSCHAPV2
OBJS += ../src/eap_server/eap_server_mschapv2.o
MS_FUNCS=y
endif

ifdef CONFIG_EAP_GTC
CFLAGS += -DEAP_SERVER_GTC
OBJS += ../src/eap_server/eap_server_gtc.o
endif

ifdef CONFIG_EAP_SIM
CFLAGS += -DEAP_SERVER_SIM
OBJS += ../src/eap_server/eap_server_sim.o
CONFIG_EAP_SIM_COMMON=y
NEED_AES_CBC=y
endif

ifdef CONFIG_EAP_AKA
CFLAGS += -DEAP_SERVER_AKA
OBJS += ../src/eap_server/eap_server_aka.o
CONFIG_EAP_SIM_COMMON=y
NEED_AES_CBC=y
endif

ifdef CONFIG_EAP_AKA_PRIME
CFLAGS += -DEAP_SERVER_AKA_PRIME
endif

ifdef CONFIG_EAP_SIM_COMMON
OBJS += ../src/eap_common/eap_sim_common.o
# Example EAP-SIM/AKA interface for GSM/UMTS authentication. This can be
# replaced with another file implementing the interface specified in
# eap_sim_db.h.
OBJS += ../src/eap_server/eap_sim_db.o
NEED_FIPS186_2_PRF=y
endif

ifdef CONFIG_EAP_PAX
CFLAGS += -DEAP_SERVER_PAX
OBJS += ../src/eap_server/eap_server_pax.o ../src/eap_common/eap_pax_common.o
endif

ifdef CONFIG_EAP_PSK
CFLAGS += -DEAP_SERVER_PSK
OBJS += ../src/eap_server/eap_server_psk.o ../src/eap_common/eap_psk_common.o
NEED_AES_ENCBLOCK=y
NEED_AES_EAX=y
endif

ifdef CONFIG_EAP_SAKE
CFLAGS += -DEAP_SERVER_SAKE
OBJS += ../src/eap_server/eap_server_sake.o ../src/eap_common/eap_sake_common.o
endif

ifdef CONFIG_EAP_GPSK
CFLAGS += -DEAP_SERVER_GPSK
OBJS += ../src/eap_server/eap_server_gpsk.o ../src/eap_common/eap_gpsk_common.o
ifdef CONFIG_EAP_GPSK_SHA256
CFLAGS += -DEAP_GPSK_SHA256
endif
endif

ifdef CONFIG_EAP_PWD
CFLAGS += -DEAP_SERVER_PWD
OBJS += ../src/eap_server/eap_server_pwd.o ../src/eap_common/eap_pwd_common.o
NEED_ECC=y
NEED_DRAGONFLY=y
endif

ifdef CONFIG_EAP_EKE
CFLAGS += -DEAP_SERVER_EKE
OBJS += ../src/eap_server/eap_server_eke.o ../src/eap_common/eap_eke_common.o
NEED_DH_GROUPS=y
NEED_DH_GROUPS_ALL=y
endif

ifdef CONFIG_EAP_VENDOR_TEST
CFLAGS += -DEAP_SERVER_VENDOR_TEST
OBJS += ../src/eap_server/eap_server_vendor_test.o
endif

ifdef CONFIG_EAP_FAST
CFLAGS += -DEAP_SERVER_FAST
OBJS += ../src/eap_server/eap_server_fast.o
OBJS += ../src/eap_common/eap_fast_common.o
TLS_FUNCS=y
NEED_T_PRF=y
NEED_AES_UNWRAP=y
endif

ifdef CONFIG_EAP_TEAP
CFLAGS += -DEAP_SERVER_TEAP
OBJS += ../src/eap_server/eap_server_teap.o
OBJS += ../src/eap_common/eap_teap_common.o
TLS_FUNCS=y
NEED_T_PRF=y
NEED_SHA384=y
NEED_TLS_PRF_SHA256=y
NEED_TLS_PRF_SHA384=y
NEED_AES_UNWRAP=y
endif

ifdef CONFIG_EAP_IKEV2
CFLAGS += -DEAP_SERVER_IKEV2
OBJS += ../src/eap_server/eap_server_ikev2.o ../src/eap_server/ikev2.o
OBJS += ../src/eap_common/eap_ikev2_common.o ../src/eap_common/ikev2_common.o
NEED_DH_GROUPS=y
NEED_DH_GROUPS_ALL=y
NEED_MODEXP=y
NEED_CIPHER=y
endif

ifdef CONFIG_EAP_TNC
CFLAGS += -DEAP_SERVER_TNC
OBJS += ../src/eap_server/eap_server_tnc.o
OBJS += ../src/eap_server/tncs.o
NEED_BASE64=y
ifndef CONFIG_DRIVER_BSD
LIBS += -ldl
endif
endif

ifdef CONFIG_EAP
CFLAGS += -DEAP_SERVER
endif

ifdef CONFIG_PKCS12
CFLAGS += -DPKCS12_FUNCS
endif

ifdef NEED_DRAGONFLY
OBJS += ../src/common/dragonfly.o
endif

ifdef MS_FUNCS
OBJS += ../src/crypto/ms_funcs.o
NEED_DES=y
NEED_MD4=y
endif

ifdef CHAP
OBJS += ../src/eap_common/chap.o
endif

ifdef TLS_FUNCS
NEED_DES=y
# Shared TLS functions (needed for EAP_TLS, EAP_PEAP, and EAP_TTLS)
CFLAGS += -DEAP_TLS_FUNCS
OBJS += ../src/eap_server/eap_server_tls_common.o
NEED_TLS_PRF=y
endif

ifndef CONFIG_TLS
CONFIG_TLS=openssl
endif

ifdef CONFIG_TLSV11
CFLAGS += -DCONFIG_TLSV11
endif

ifdef CONFIG_TLSV12
CFLAGS += -DCONFIG_TLSV12
endif

ifeq ($(CONFIG_TLS), openssl)
CONFIG_CRYPTO=openssl
ifdef TLS_FUNCS
OBJS += ../src/crypto/tls_openssl.o
OBJS += ../src/crypto/tls_openssl_ocsp.o
LIBS += -lssl
endif
OBJS += ../src/crypto/crypto_openssl.o
ifdef NEED_FIPS186_2_PRF
OBJS += ../src/crypto/fips_prf_openssl.o
endif
NEED_TLS_PRF_SHA256=y
LIBS += -lcrypto
ifdef CONFIG_TLS_ADD_DL
LIBS += -ldl
endif
ifndef CONFIG_TLS_DEFAULT_CIPHERS
CONFIG_TLS_DEFAULT_CIPHERS = "DEFAULT:!EXP:!LOW"
endif
CFLAGS += -DTLS_DEFAULT_CIPHERS=\"$(CONFIG_TLS_DEFAULT_CIPHERS)\"
endif

ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), wolfssl)
AESOBJS += ../src/crypto/aes-wrap.o
endif
endif

ifdef NEED_AES_EAX
AESOBJS += ../src/crypto/aes-eax.o
NEED_AES_CTR=y
endif

ifdef NEED_AES_SIV
AESOBJS += ../src/crypto/aes-siv.o
NEED_AES_CTR=y
endif

ifdef NEED_AES_CTR
AESOBJS += ../src/crypto/aes-ctr.o
endif

ifdef NEED_AES_ENCBLOCK
AESOBJS += ../src/crypto/aes-encblock.o
endif

ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), wolfssl)
AESOBJS += ../src/crypto/aes-omac1.o
endif
endif

ifdef NEED_AES_UNWRAP
ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), wolfssl)
NEED_AES_DEC=y
AESOBJS += ../src/crypto/aes-unwrap.o
endif
endif
endif
endif

ifdef NEED_AES_CBC
NEED_AES_DEC=y
ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), wolfssl)
AESOBJS += ../src/crypto/aes-cbc.o
endif
endif
endif
endif

ifdef NEED_AES_DEC
ifdef CONFIG_INTERNAL_AES
AESOBJS += ../src/crypto/aes-internal-dec.o
endif
endif

ifdef NEED_AES
OBJS += $(AESOBJS)
endif

ifdef NEED_SHA1
ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), gnutls)
ifneq ($(CONFIG_TLS), wolfssl)
SHA1OBJS += ../src/crypto/sha1.o
endif
endif
endif
endif
SHA1OBJS += ../src/crypto/sha1-prf.o
ifdef CONFIG_INTERNAL_SHA1
SHA1OBJS += ../src/crypto/sha1-internal.o
ifdef NEED_FIPS186_2_PRF
SHA1OBJS += ../src/crypto/fips_prf_internal.o
endif
endif
ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), wolfssl)
SHA1OBJS += ../src/crypto/sha1-pbkdf2.o
endif
endif
ifdef NEED_T_PRF
SHA1OBJS += ../src/crypto/sha1-tprf.o
endif
ifdef NEED_TLS_PRF
SHA1OBJS += ../src/crypto/sha1-tlsprf.o
endif
endif

ifdef NEED_SHA1
OBJS += $(SHA1OBJS)
endif

ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), gnutls)
ifneq ($(CONFIG_TLS), wolfssl)
OBJS += ../src/crypto/md5.o
endif
endif
endif
endif

ifdef NEED_MD5
ifdef CONFIG_INTERNAL_MD5
OBJS += ../src/crypto/md5-internal.o
endif
endif

ifdef NEED_MD4
ifdef CONFIG_INTERNAL_MD4
OBJS += ../src/crypto/md4-internal.o
endif
endif

ifdef NEED_DES
CFLAGS += -DCONFIG_DES
ifdef CONFIG_INTERNAL_DES
OBJS += ../src/crypto/des-internal.o
endif
endif

ifdef CONFIG_NO_RC4
CFLAGS += -DCONFIG_NO_RC4
endif

ifdef NEED_RC4
ifdef CONFIG_INTERNAL_RC4
ifndef CONFIG_NO_RC4
OBJS += ../src/crypto/rc4.o
endif
endif
endif

CFLAGS += -DCONFIG_SHA256
ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), gnutls)
ifneq ($(CONFIG_TLS), wolfssl)
OBJS += ../src/crypto/sha256.o
endif
endif
endif
endif
OBJS += ../src/crypto/sha256-prf.o
ifdef CONFIG_INTERNAL_SHA256
OBJS += ../src/crypto/sha256-internal.o
endif
ifdef NEED_TLS_PRF_SHA256
OBJS += ../src/crypto/sha256-tlsprf.o
endif
ifdef NEED_TLS_PRF_SHA384
OBJS += ../src/crypto/sha384-tlsprf.o
endif
ifdef NEED_HMAC_SHA256_KDF
OBJS += ../src/crypto/sha256-kdf.o
endif
ifdef NEED_HMAC_SHA384_KDF
OBJS += ../src/crypto/sha384-kdf.o
endif
ifdef NEED_HMAC_SHA512_KDF
OBJS += ../src/crypto/sha512-kdf.o
endif
ifdef NEED_SHA384
CFLAGS += -DCONFIG_SHA384
ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), gnutls)
ifneq ($(CONFIG_TLS), wolfssl)
OBJS += ../src/crypto/sha384.o
endif
endif
endif
endif
OBJS += ../src/crypto/sha384-prf.o
endif
ifdef NEED_SHA512
CFLAGS += -DCONFIG_SHA512
ifneq ($(CONFIG_TLS), openssl)
ifneq ($(CONFIG_TLS), linux)
ifneq ($(CONFIG_TLS), gnutls)
ifneq ($(CONFIG_TLS), wolfssl)
OBJS += ../src/crypto/sha512.o
endif
endif
endif
endif
OBJS += ../src/crypto/sha512-prf.o
endif

ifdef CONFIG_INTERNAL_SHA384
CFLAGS += -DCONFIG_INTERNAL_SHA384
OBJS += ../src/crypto/sha384-internal.o
endif

ifdef CONFIG_INTERNAL_SHA512
CFLAGS += -DCONFIG_INTERNAL_SHA512
OBJS += ../src/crypto/sha512-internal.o
endif

ifdef NEED_ASN1
OBJS += ../src/tls/asn1.o
endif

ifdef NEED_DH_GROUPS
OBJS += ../src/crypto/dh_groups.o
endif
ifdef NEED_DH_GROUPS_ALL
CFLAGS += -DALL_DH_GROUPS
endif
ifdef CONFIG_INTERNAL_DH_GROUP5
ifdef NEED_DH_GROUPS
OBJS += ../src/crypto/dh_group5.o
endif
endif

ifdef NEED_ECC
CFLAGS += -DCONFIG_ECC
endif

ifdef CONFIG_NO_RANDOM_POOL
CFLAGS += -DCONFIG_NO_RANDOM_POOL
else
ifdef CONFIG_GETRANDOM
CFLAGS += -DCONFIG_GETRANDOM
endif
OBJS += ../src/crypto/random.o
endif

UTILS_LIB += ../src/utils/libutils.a

OBJS_peer += ../src/eap_peer/eap_tls.o
OBJS_peer += ../src/eap_peer/eap_peap.o
OBJS_peer += ../src/eap_peer/eap_ttls.o
OBJS_peer += ../src/eap_peer/eap_md5.o
OBJS_peer += ../src/eap_peer/eap_mschapv2.o
OBJS_peer += ../src/eap_peer/mschapv2.o
OBJS_peer += ../src/eap_peer/eap_otp.o
OBJS_peer += ../src/eap_peer/eap_gtc.o
OBJS_peer += ../src/eap_peer/eap_leap.o
OBJS_peer += ../src/eap_peer/eap_psk.o
OBJS_peer += ../src/eap_peer/eap_pax.o
OBJS_peer += ../src/eap_peer/eap_sake.o
OBJS_peer += ../src/eap_peer/eap_gpsk.o
OBJS_peer += ../src/eap_peer/eap.o
OBJS_peer += ../src/eap_common/eap_common.o
OBJS_peer += ../src/eap_peer/eap_methods.o
OBJS_peer += ../src/eap_peer/eap_tls_common.o

CFLAGS += -DEAP_TLS
CFLAGS += -DEAP_PEAP
CFLAGS += -DEAP_TTLS
CFLAGS += -DEAP_MD5
CFLAGS += -DEAP_MSCHAPv2
CFLAGS += -DEAP_GTC
CFLAGS += -DEAP_OTP
CFLAGS += -DEAP_LEAP
CFLAGS += -DEAP_PSK
CFLAGS += -DEAP_PAX
CFLAGS += -DEAP_SAKE
CFLAGS += -DEAP_GPSK

CFLAGS += -DEAP_SERVER_IDENTITY
CFLAGS += -DEAP_SERVER_GPSK_SHA256
CFLAGS += -DIEEE8021X_EAPOL

# Optional components to add EAP server support
OBJS_server += ../src/eap_server/eap_server.o
OBJS_server += ../src/eap_server/eap_server_identity.o
OBJS_server += ../src/eap_server/eap_server_methods.o

OBJS_lib=$(OBJS) $(OBJS_peer) $(OBJS_server)
_OBJS_VAR := OBJS_lib
include ../src/objs.mk

_OBJS_VAR := UTILS_LIB
include ../src/objs.mk

#OBJS_ex = eap_example.o eap_example_peer.o eap_example_server.o
#_OBJS_VAR := OBJS_ex
#include ../src/objs.mk

#eap_example: $(OBJS_ex) $(UTILS_LIB)
#	$(LDO) $(LDFLAGS) -o eap_example $(OBJS_ex) -L. -leap $(LIBS)

ifneq ($(CONFIG_SOLIB), yes)
alib = libeap.a
$(alib): $(UTILS_LIB) $(OBJS_lib)
	$(AR) crT $(alib) $^
	$(RANLIB) $(alib)
else
CFLAGS  += -fPIC -DPIC
LDFLAGS += -shared
alib = libeap.so
$(alib): $(UTILS_LIB) $(OBJS_lib)
	$(LDO) $(LDFLAGS) $^ -o $(alib) -L. $(LIBS)

endif

.PHONY: clean
clean: common-clean
	rm -f core *~ *.o *.d $(alib)

print-%  : ; @echo $* = $($*)

.PHONY: install
install: $(alib)
	mkdir -p $(INSTALL_DIR)/lib
	cp $^ $(INSTALL_DIR)/lib
	mkdir -p $(INSTALL_DIR)/include/eap_common
	cp ../src/eap_common/*.h $(INSTALL_DIR)/include/eap_common
	mkdir -p $(INSTALL_DIR)/include/eap_peer
	cp ../src/eap_peer/*.h $(INSTALL_DIR)/include/eap_peer
	mkdir -p $(INSTALL_DIR)/include/eap_server
	cp ../src/eap_server/*.h $(INSTALL_DIR)/include/eap_server
	mkdir -p $(INSTALL_DIR)/include/crypto
	cp ../src/crypto/*.h $(INSTALL_DIR)/include/crypto
	mkdir -p $(INSTALL_DIR)/include/tls
	cp ../src/tls/*.h $(INSTALL_DIR)/include/tls
	mkdir -p $(INSTALL_DIR)/include/utils
	cp ../src/utils/*.h $(INSTALL_DIR)/include/utils
	mkdir -p $(INSTALL_DIR)/include/common
	cp ../src/common/*.h $(INSTALL_DIR)/include/common

-include $(OBJS:%.o=%.d)
