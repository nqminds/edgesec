#ifndef MIDDLEWARES_LIST_H
#define MIDDLEWARES_LIST_H

#include <sqlite3.h>
#include <pcap.h>
#include "middleware.h"
#include "../utils/eloop.h"

struct middleware_handlers {
  const struct capture_middleware f;
  struct middleware_context *context;
};

static const UT_icd middleware_icd = {sizeof(struct middleware_handlers), NULL,
                                      NULL, NULL};

UT_array *assign_middlewares(void);

static inline int init_middlewares(UT_array *handlers, sqlite3 *db,
                                   char *db_path, struct eloop_data *eloop,
                                   struct pcap_context *pc) {
  struct middleware_handlers *handler = NULL;

  while ((handler =
              (struct middleware_handlers *)utarray_next(handlers, handler))) {
    log_trace("Initialising capture middleware: %s", handler->f.name);
    handler->context = handler->f.init(db, db_path, eloop, pc);
    if (handler->context == NULL) {
      log_error("handle init error");
      return -1;
    }
  }

  return 0;
}

static inline void free_middlewares(UT_array *handlers) {
  struct middleware_handlers *handler = NULL;

  while ((handler =
              (struct middleware_handlers *)utarray_next(handlers, handler))) {
    handler->f.free(handler->context);
    handler->context = NULL;
  }

  utarray_free(handlers);
}

static inline void process_middlewares(UT_array *handlers, char *ltype,
                                       struct pcap_pkthdr *header,
                                       uint8_t *packet, char *ifname) {
  struct middleware_handlers *handler = NULL;

  while ((handler =
              (struct middleware_handlers *)utarray_next(handlers, handler))) {
    if (handler->f.process(handler->context, ltype, header, packet, ifname) <
        0) {
      log_error("handler process fail");
    }
  }
}

#endif /* !MIDDLEWARES_LIST_H */
