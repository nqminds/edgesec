/**
 * @file middlewares_list.h
 * @authors Alexandru Mereacre, Alois Klink
 * @brief File containing the definition of generic middleware creation
 * functions.
 * @details The CMake function `edgesecAddCaptureMiddleware` generated a custom
 * middlewares_list.c.in file containing the list of middlewares to be used.
 *
 * Because of this, there may be no middlewares, some middle wares,
 * or even middlewares created by the user.
 */

#ifndef MIDDLEWARES_LIST_H
#define MIDDLEWARES_LIST_H

#include <sqlite3.h>
#include <pcap.h>
#include <utarray.h>
#include "middleware.h"
#include <eloop.h>

/**
 * @brief Generic middleware context and functions.
 */
struct middleware_handlers {
  /**
   * @brief The implementation of the middleware functions.
   */
  const struct capture_middleware f;
  /**
   * @brief The storage of the middleware.
   * This should be created by #capture_middleware::init() and freed with
   * #capture_middleware::free() when the context is no longer required.
   */
  struct middleware_context *context;
};

/** @brief Middleware UT_array definition */
static const UT_icd middleware_icd = {sizeof(struct middleware_handlers), NULL,
                                      NULL, NULL};

/**
 * @brief Constructs the list of middlewares to use.
 * @details The list of middlewares is created by the CMake function
 * `edgesecAddCaptureMiddleware`. This list may be empty, or contain some
 * middlewares, or even middlewares created by the user. When you are finished
 * with this list, call free_middlewares() to free it.
 * @return The list of uninitialised middlewares.
 */
UT_array *assign_middlewares(void);

/**
 * @brief Initialises all the middlewares.
 *
 * @param[in] handlers The list of middlewares created from
 * assign_middlewares().
 * @param[in] db The SQLite database.
 * @param[in] db_path The path to the SQLite database.
 * @param[in] eloop Global event loop data.
 * @param[in] pc The pcap context created by run_pcap()
 * @param[in] params The middleware params
 * @retval 0 on success.
 * @retval -1 on error.
 */
static inline int init_middlewares(UT_array *handlers, sqlite3 *db,
                                   char *db_path, struct eloop_data *eloop,
                                   struct pcap_context *pc, char *params) {
  struct middleware_handlers *handler = NULL;

  while ((handler =
              (struct middleware_handlers *)utarray_next(handlers, handler))) {
    log_trace("Initialising capture middleware: %s", handler->f.name);
    handler->context = handler->f.init(db, db_path, eloop, pc, params);
    if (handler->context == NULL) {
      log_error("handle init error");
      return -1;
    }
  }

  return 0;
}

/**
 * @brief Frees middlewares created by assign_middlewares().
 *
 * @param[in] handlers The list of middlewares from assign_middlewares() to
 * free.
 */
static inline void free_middlewares(UT_array *handlers) {
  struct middleware_handlers *handler = NULL;

  if (handlers == NULL) {
    return;
  }

  while ((handler =
              (struct middleware_handlers *)utarray_next(handlers, handler))) {
    handler->f.free(handler->context);
    handler->context = NULL;
  }

  utarray_free(handlers);
}

/**
 * @brief Runs all the middlewares.
 *
 * An error is logged if any of the handlers fail.
 *
 * @param[in] handlers The list of middlewares to run.
 * @param[in] ltype The packet type.
 * @param[in] header The PCAP packet header.
 * @param[in] packet The PCAP packet.
 * @param[in] ifname The name of the capture interface.
 */
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
