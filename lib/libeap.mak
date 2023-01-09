# SPDX-FileCopyrightText: © 2007, Jouni Malinen <j@w1.fi>
# SPDX-FileCopyrightText: © 2023, Edgesec contributors
# SPDX-License-Identifier: BSD-3-clause
#
# This Makefile is adapted from https://w1.fi/cgit/hostap/tree/eap_example/Makefile?h=hostap_2_10
# The main added feature is a `make install` command.

CONFIG_FILE = .config

include ../src/build.rules

CFLAGS += -I.
CFLAGS += -I../src
CFLAGS += -I../src/utils


EAP_LIBS += ../src/utils/libutils.a
EAP_LIBS += ../src/crypto/libcrypto.a
EAP_LIBS += ../src/tls/libtls.a

OBJS_both += ../src/eap_common/eap_peap_common.o
OBJS_both += ../src/eap_common/eap_psk_common.o
OBJS_both += ../src/eap_common/eap_pax_common.o
OBJS_both += ../src/eap_common/eap_sake_common.o
OBJS_both += ../src/eap_common/eap_gpsk_common.o
OBJS_both += ../src/eap_common/chap.o

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
CFLAGS += -DEAP_GPSK -DEAP_GPSK_SHA256

CFLAGS += -DEAP_SERVER_IDENTITY
CFLAGS += -DEAP_SERVER_TLS
CFLAGS += -DEAP_SERVER_PEAP
CFLAGS += -DEAP_SERVER_TTLS
CFLAGS += -DEAP_SERVER_MD5
CFLAGS += -DEAP_SERVER_MSCHAPV2
CFLAGS += -DEAP_SERVER_GTC
CFLAGS += -DEAP_SERVER_PSK
CFLAGS += -DEAP_SERVER_PAX
CFLAGS += -DEAP_SERVER_SAKE
CFLAGS += -DEAP_SERVER_GPSK -DEAP_SERVER_GPSK_SHA256

CFLAGS += -DIEEE8021X_EAPOL


# Optional components to add EAP server support
OBJS_server += ../src/eap_server/eap_server_tls.o
OBJS_server += ../src/eap_server/eap_server_peap.o
OBJS_server += ../src/eap_server/eap_server_ttls.o
OBJS_server += ../src/eap_server/eap_server_md5.o
OBJS_server += ../src/eap_server/eap_server_mschapv2.o
OBJS_server += ../src/eap_server/eap_server_gtc.o
OBJS_server += ../src/eap_server/eap_server_psk.o
OBJS_server += ../src/eap_server/eap_server_pax.o
OBJS_server += ../src/eap_server/eap_server_sake.o
OBJS_server += ../src/eap_server/eap_server_gpsk.o
OBJS_server += ../src/eap_server/eap_server.o
OBJS_server += ../src/eap_server/eap_server_identity.o
OBJS_server += ../src/eap_server/eap_server_methods.o
OBJS_server += ../src/eap_server/eap_server_tls_common.o

CFLAGS += -DEAP_SERVER


OBJS_lib=$(OBJS_both) $(OBJS_peer) $(OBJS_server)
_OBJS_VAR := OBJS_lib
include ../src/objs.mk

OBJS_ex = eap_example.o eap_example_peer.o eap_example_server.o
_OBJS_VAR := OBJS_ex
include ../src/objs.mk

_OBJS_VAR := EAP_LIBS
include ../src/objs.mk


ifneq ($(CONFIG_SOLIB), yes)
LIBEAP = libeap.a
libeap.a: $(EAP_LIBS) $(OBJS_lib)
	$(AR) crT libeap.a $^
	$(RANLIB) libeap.a

else
CFLAGS  += -fPIC -DPIC
LDFLAGS += -shared

LIBEAP  = libeap.so
libeap.so: $(EAP_LIBS) $(OBJS_lib)
	$(LDO) $(LDFLAGS) $^ -o $(LIBEAP)

endif

ALL=$(LIBEAP)
INSTALL_DIR=$(CONFIG_LIBEAP_INSTALL_DIR)

.PHONY: install
install: $(LIBEAP)
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
	mkdir -p $(INSTALL_DIR)/include/utils
	cp ../src/utils/*.h $(INSTALL_DIR)/include/utils
	mkdir -p $(INSTALL_DIR)/include/tls
	cp ../src/tls/*.h $(INSTALL_DIR)/include/tls
	mkdir -p $(INSTALL_DIR)/include/common
	cp ../src/common/*.h $(INSTALL_DIR)/include/common

clean: common-clean
	rm -f core *~ *.o *.d libeap.a libeap.so

-include $(OBJS:%.o=%.d)
