/*
 * Event loop based on select() loop
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/**
 * @file eloop.c
 * @author Jouni Malinen
 * @brief Event loop.
 */

// #include "includes.h"
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "log.h"
#include "allocs.h"
#include "os.h"
#include "list.h"
#include "eloop.h"

struct eloop_data *eloop_init(void) {
  struct eloop_data *eloop = NULL;

  if ((eloop = os_zalloc(sizeof(struct eloop_data))) == NULL) {
    log_errno("os_zalloc");
    return NULL;
  }

  dl_list_init(&(eloop->timeout));
  eloop->epollfd = epoll_create1(0);
  if (eloop->epollfd < 0) {
    log_errno("epoll_create1 failed");
    return NULL;
  }

  eloop->readers.type = EVENT_TYPE_READ;
  eloop->writers.type = EVENT_TYPE_WRITE;
  eloop->exceptions.type = EVENT_TYPE_EXCEPTION;

  return eloop;
}

static int eloop_sock_queue(struct eloop_data *eloop, int sock,
                            eloop_event_type type) {
  struct epoll_event ev;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  os_memset(&ev, 0, sizeof(ev));
  switch (type) {
    case EVENT_TYPE_READ:
      ev.events = EPOLLIN;
      break;
    case EVENT_TYPE_WRITE:
      ev.events = EPOLLOUT;
      break;
    /*
     * Exceptions are always checked when using epoll, but I suppose it's
     * possible that someone registered a socket *only* for exception
     * handling.
     */
    case EVENT_TYPE_EXCEPTION:
      ev.events = EPOLLERR | EPOLLHUP;
      break;
  }
  ev.data.fd = sock;
  if (epoll_ctl(eloop->epollfd, EPOLL_CTL_ADD, sock, &ev) < 0) {
    log_errno("epoll_ctl(ADD) for fd=%d failed", sock);
    return -1;
  }
  return 0;
}

static int eloop_sock_table_add_sock(struct eloop_data *eloop,
                                     struct eloop_sock_table *table, int sock,
                                     eloop_sock_handler handler,
                                     void *eloop_data, void *user_data) {
  struct epoll_event *temp_events;
  struct eloop_sock *temp_table;
  int next;
  struct eloop_sock *tmp;
  int new_max_sock;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  if (sock > eloop->max_sock)
    new_max_sock = sock;
  else
    new_max_sock = eloop->max_sock;

  if (table == NULL)
    return -1;

  if (new_max_sock >= eloop->max_fd) {
    next = new_max_sock + 16;
    temp_table =
        os_realloc_array(eloop->fd_table, next, sizeof(struct eloop_sock));
    if (temp_table == NULL)
      return -1;

    eloop->max_fd = next;
    eloop->fd_table = temp_table;
  }

  if (eloop->count + 1 > eloop->epoll_max_event_num) {
    next = eloop->epoll_max_event_num == 0 ? 8 : eloop->epoll_max_event_num * 2;
    temp_events =
        os_realloc_array(eloop->epoll_events, next, sizeof(struct epoll_event));
    if (temp_events == NULL) {
      log_errno("os_malloc for epoll failed");
      return -1;
    }

    eloop->epoll_max_event_num = next;
    eloop->epoll_events = temp_events;
  }

  tmp = os_realloc_array(table->table, table->count + 1,
                         sizeof(struct eloop_sock));
  if (tmp == NULL) {
    return -1;
  }

  tmp[table->count].sock = sock;
  tmp[table->count].eloop_data = eloop_data;
  tmp[table->count].user_data = user_data;
  tmp[table->count].handler = handler;

  table->count++;
  table->table = tmp;
  eloop->max_sock = new_max_sock;
  eloop->count++;
  table->changed = 1;

  if (eloop_sock_queue(eloop, sock, table->type) < 0)
    return -1;
  os_memcpy(&eloop->fd_table[sock], &table->table[table->count - 1],
            sizeof(struct eloop_sock));
  return 0;
}

static void eloop_sock_table_remove_sock(struct eloop_data *eloop,
                                         struct eloop_sock_table *table,
                                         int sock) {
  int i;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return;
  }

  if (table == NULL || table->table == NULL || table->count == 0)
    return;

  for (i = 0; i < table->count; i++) {
    if (table->table[i].sock == sock)
      break;
  }
  if (i == table->count)
    return;

  if (i != table->count - 1) {
    os_memmove(&table->table[i], &table->table[i + 1],
               (table->count - i - 1) * sizeof(struct eloop_sock));
  }
  table->count--;
  eloop->count--;
  table->changed = 1;

  if (epoll_ctl(eloop->epollfd, EPOLL_CTL_DEL, sock, NULL) < 0) {
    log_errno("epoll_ctl(DEL) for fd=%d failed", sock);
    return;
  }
  os_memset(&eloop->fd_table[sock], 0, sizeof(struct eloop_sock));
}

static void eloop_sock_table_dispatch(struct eloop_data *eloop,
                                      struct epoll_event *events, int nfds) {
  struct eloop_sock *table;
  int i;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return;
  }

  for (i = 0; i < nfds; i++) {
    table = &eloop->fd_table[events[i].data.fd];
    if (table->handler == NULL)
      continue;
    table->handler(table->sock, table->eloop_data, table->user_data);
    if (eloop->readers.changed || eloop->writers.changed ||
        eloop->exceptions.changed)
      break;
  }
}

static void eloop_sock_table_destroy(struct eloop_sock_table *table) {
  if (table != NULL) {
    int i;
    for (i = 0; i < table->count && table->table; i++) {
      log_trace("ELOOP: remaining socket: sock=%d eloop_data=%p user_data=%p "
                "handler=%p",
                table->table[i].sock, table->table[i].eloop_data,
                table->table[i].user_data, table->table[i].handler);
    }
    os_free(table->table);
  }
}

int eloop_register_read_sock(struct eloop_data *eloop, int sock,
                             eloop_sock_handler handler, void *eloop_data,
                             void *user_data) {
  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  return eloop_register_sock(eloop, sock, EVENT_TYPE_READ, handler, eloop_data,
                             user_data);
}

void eloop_unregister_read_sock(struct eloop_data *eloop, int sock) {
  eloop_unregister_sock(eloop, sock, EVENT_TYPE_READ);
}

static struct eloop_sock_table *eloop_get_sock_table(struct eloop_data *eloop,
                                                     eloop_event_type type) {
  if (eloop == NULL) {
    return NULL;
  }

  switch (type) {
    case EVENT_TYPE_READ:
      return &eloop->readers;
    case EVENT_TYPE_WRITE:
      return &eloop->writers;
    case EVENT_TYPE_EXCEPTION:
      return &eloop->exceptions;
  }

  return NULL;
}

int eloop_register_sock(struct eloop_data *eloop, int sock,
                        eloop_event_type type, eloop_sock_handler handler,
                        void *eloop_data, void *user_data) {
  struct eloop_sock_table *table;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  assert(sock >= 0);
  table = eloop_get_sock_table(eloop, type);
  return eloop_sock_table_add_sock(eloop, table, sock, handler, eloop_data,
                                   user_data);
}

void eloop_unregister_sock(struct eloop_data *eloop, int sock,
                           eloop_event_type type) {
  struct eloop_sock_table *table;

  table = eloop_get_sock_table(eloop, type);
  eloop_sock_table_remove_sock(eloop, table, sock);
}

int eloop_register_timeout(struct eloop_data *eloop, unsigned long secs,
                           unsigned long usecs, eloop_timeout_handler handler,
                           void *eloop_data, void *user_data) {
  struct eloop_timeout *timeout, *tmp;
  os_time_t now_sec, now_usec;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  timeout = os_zalloc(sizeof(*timeout));
  if (timeout == NULL)
    return -1;
  if (os_get_reltime(&timeout->time) < 0) {
    os_free(timeout);
    return -1;
  }
  now_sec = timeout->time.sec;
  now_usec = timeout->time.usec;
  timeout->time.sec += secs;
  if (timeout->time.sec < now_sec) {
    /*
     * Integer overflow - assume long enough timeout to be assumed
     * to be infinite, i.e., the timeout would never happen.
     */
    log_trace("ELOOP: Too long timeout (secs=%u) to ever happen - ignore it",
              secs);
    os_free(timeout);
    return 0;
  }
  timeout->time.usec += usecs;
  if (timeout->time.usec < now_usec) {
    log_trace("ELOOP: Overflow for long timeout (usecs=%u) - ignore it", usecs);
    os_free(timeout);
    return 0;
  }

  while (timeout->time.usec >= 1000000) {
    timeout->time.sec++;
    timeout->time.usec -= 1000000;
  }
  timeout->eloop_data = eloop_data;
  timeout->user_data = user_data;
  timeout->handler = handler;

  /* Maintain timeouts in order of increasing time */
  dl_list_for_each(tmp, &eloop->timeout, struct eloop_timeout, list) {
    if (os_reltime_before(&timeout->time, &tmp->time)) {
      dl_list_add(tmp->list.prev, &timeout->list);
      return 0;
    }
  }
  dl_list_add_tail(&eloop->timeout, &timeout->list);

  return 0;
}

static void eloop_remove_timeout(struct eloop_timeout *timeout) {
  if (timeout == NULL) {
    log_error("timeout is NULL");
    return;
  }

  dl_list_del(&timeout->list);
  os_free(timeout);
}

int eloop_cancel_timeout(struct eloop_data *eloop,
                         eloop_timeout_handler handler, void *eloop_data,
                         void *user_data) {
  struct eloop_timeout *timeout, *prev;
  int removed = 0;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  dl_list_for_each_safe(timeout, prev, &eloop->timeout, struct eloop_timeout,
                        list) {
    if (timeout->handler == handler &&
        (timeout->eloop_data == eloop_data || eloop_data == ELOOP_ALL_CTX) &&
        (timeout->user_data == user_data || user_data == ELOOP_ALL_CTX)) {
      eloop_remove_timeout(timeout);
      removed++;
    }
  }

  return removed;
}

int eloop_cancel_timeout_one(struct eloop_data *eloop,
                             eloop_timeout_handler handler, void *eloop_data,
                             void *user_data, struct os_reltime *remaining) {
  struct eloop_timeout *timeout, *prev;
  int removed = 0;
  struct os_reltime now;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  os_get_reltime(&now);
  remaining->sec = remaining->usec = 0;

  dl_list_for_each_safe(timeout, prev, &eloop->timeout, struct eloop_timeout,
                        list) {
    if (timeout->handler == handler && (timeout->eloop_data == eloop_data) &&
        (timeout->user_data == user_data)) {
      removed = 1;
      if (os_reltime_before(&now, &timeout->time))
        os_reltime_sub(&timeout->time, &now, remaining);
      eloop_remove_timeout(timeout);
      break;
    }
  }
  return removed;
}

int eloop_is_timeout_registered(struct eloop_data *eloop,
                                eloop_timeout_handler handler, void *eloop_data,
                                void *user_data) {
  struct eloop_timeout *tmp;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  dl_list_for_each(tmp, &eloop->timeout, struct eloop_timeout, list) {
    if (tmp->handler == handler && tmp->eloop_data == eloop_data &&
        tmp->user_data == user_data)
      return 1;
  }

  return 0;
}

int eloop_deplete_timeout(struct eloop_data *eloop, unsigned long req_secs,
                          unsigned long req_usecs,
                          eloop_timeout_handler handler, void *eloop_data,
                          void *user_data) {
  struct os_reltime now, requested, remaining;
  struct eloop_timeout *tmp;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  dl_list_for_each(tmp, &eloop->timeout, struct eloop_timeout, list) {
    if (tmp->handler == handler && tmp->eloop_data == eloop_data &&
        tmp->user_data == user_data) {
      requested.sec = req_secs;
      requested.usec = req_usecs;
      os_get_reltime(&now);
      os_reltime_sub(&tmp->time, &now, &remaining);
      if (os_reltime_before(&requested, &remaining)) {
        eloop_cancel_timeout(eloop, handler, eloop_data, user_data);
        eloop_register_timeout(eloop, requested.sec, requested.usec, handler,
                               eloop_data, user_data);
        return 1;
      }
      return 0;
    }
  }

  return -1;
}

int eloop_replenish_timeout(struct eloop_data *eloop, unsigned long req_secs,
                            unsigned long req_usecs,
                            eloop_timeout_handler handler, void *eloop_data,
                            void *user_data) {
  struct os_reltime now, requested, remaining;
  struct eloop_timeout *tmp;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  dl_list_for_each(tmp, &eloop->timeout, struct eloop_timeout, list) {
    if (tmp->handler == handler && tmp->eloop_data == eloop_data &&
        tmp->user_data == user_data) {
      requested.sec = req_secs;
      requested.usec = req_usecs;
      os_get_reltime(&now);
      os_reltime_sub(&tmp->time, &now, &remaining);
      if (os_reltime_before(&remaining, &requested)) {
        eloop_cancel_timeout(eloop, handler, eloop_data, user_data);
        eloop_register_timeout(eloop, requested.sec, requested.usec, handler,
                               eloop_data, user_data);
        return 1;
      }
      return 0;
    }
  }

  return -1;
}

// static void eloop_handle_alarm(int sig) {
//   (void)sig;
//   log_trace("eloop: could not process SIGINT or SIGTERM in "
//             "two seconds. Looks like there\n"
//             "is a bug that ends up in a busy loop that "
//             "prevents clean shutdown.\n"
//             "Killing program forcefully.");
//   exit(1);
// }

// static void eloop_handle_signal(int sig) {
//   int i;

//   if ((sig == SIGINT || sig == SIGTERM) && !eloop->pending_terminate) {
//     /* Use SIGALRM to break out from potential busy loops that
//      * would not allow the program to be killed. */
//     eloop->pending_terminate = 1;
//     signal(SIGALRM, eloop_handle_alarm);
//     alarm(2);
//   }

//   eloop->signaled++;
//   for (i = 0; i < eloop->signal_count; i++) {
//     if (eloop->signals[i].sig == sig) {
//       eloop->signals[i].signaled++;
//       break;
//     }
//   }
// }

// static void eloop_process_pending_signals(struct eloop_data *eloop) {
//   int i;

//   if (eloop->signaled == 0)
//     return;
//   eloop->signaled = 0;

//   if (eloop->pending_terminate) {
//     alarm(0);
//     eloop->pending_terminate = 0;
//   }

//   for (i = 0; i < eloop->signal_count; i++) {
//     if (eloop->signals[i].signaled) {
//       eloop->signals[i].signaled = 0;
//       eloop->signals[i].handler(eloop->signals[i].sig,
//                                eloop->signals[i].user_data);
//     }
//   }
// }

// int eloop_register_signal(struct eloop_data *eloop,
//                           int sig, eloop_signal_handler handler,
//                           void *user_data) {
//   struct eloop_signal *tmp;

//   tmp = os_realloc_array(eloop->signals, eloop->signal_count + 1,
//                          sizeof(struct eloop_signal));
//   if (tmp == NULL)
//     return -1;

//   tmp[eloop->signal_count].sig = sig;
//   tmp[eloop->signal_count].user_data = user_data;
//   tmp[eloop->signal_count].handler = handler;
//   tmp[eloop->signal_count].signaled = 0;
//   eloop->signal_count++;
//   eloop->signals = tmp;
//   signal(sig, eloop_handle_signal);

//   return 0;
// }

// int eloop_register_signal_terminate(struct eloop_data *eloop,
//                                     eloop_signal_handler handler,
//                                     void *user_data) {
//   int ret = eloop_register_signal(eloop, SIGINT, handler, user_data);
//   if (ret == 0)
//     ret = eloop_register_signal(eloop, SIGTERM, handler, user_data);
//   return ret;
// }

// int eloop_register_signal_reconfig(struct eloop_data *eloop,
//                                    eloop_signal_handler handler,
//                                    void *user_data) {
//   return eloop_register_signal(eloop, SIGHUP, handler, user_data);
// }

void eloop_run(struct eloop_data *eloop) {
  int timeout_ms = -1;
  int res;
  struct os_reltime tv, now;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return;
  }

  while (!eloop->terminate &&
         (!dl_list_empty(&eloop->timeout) || eloop->readers.count > 0 ||
          eloop->writers.count > 0 || eloop->exceptions.count > 0)) {
    struct eloop_timeout *timeout;

    // if (eloop->pending_terminate) {
    //   /*
    //    * This may happen in some corner cases where a signal
    //    * is received during a blocking operation. We need to
    //    * process the pending signals and exit if requested to
    //    * avoid hitting the SIGALRM limit if the blocking
    //    * operation took more than two seconds.
    //    */
    //   eloop_process_pending_signals(eloop);
    //   if (eloop->terminate)
    //     break;
    // }

    timeout = dl_list_first(&eloop->timeout, struct eloop_timeout, list);
    if (timeout) {
      os_get_reltime(&now);
      if (os_reltime_before(&now, &timeout->time))
        os_reltime_sub(&timeout->time, &now, &tv);
      else
        tv.sec = tv.usec = 0;
      timeout_ms = tv.sec * 1000 + tv.usec / 1000;
    }

    if (eloop->count == 0) {
      res = 0;
    } else {
      res = epoll_wait(eloop->epollfd, eloop->epoll_events, eloop->count,
                       timeout_ms);
    }
    if (res < 0 && errno != EINTR && errno != 0) {
      log_errno("eloop");
      goto out;
    }

    eloop->readers.changed = 0;
    eloop->writers.changed = 0;
    eloop->exceptions.changed = 0;

    // eloop_process_pending_signals(eloop);

    /* check if some registered timeouts have occurred */
    timeout = dl_list_first(&eloop->timeout, struct eloop_timeout, list);
    if (timeout) {
      os_get_reltime(&now);
      if (!os_reltime_before(&now, &timeout->time)) {
        void *eloop_data = timeout->eloop_data;
        void *user_data = timeout->user_data;
        eloop_timeout_handler handler = timeout->handler;
        eloop_remove_timeout(timeout);
        handler(eloop_data, user_data);
      }
    }

    if (res <= 0)
      continue;

    if (eloop->readers.changed || eloop->writers.changed ||
        eloop->exceptions.changed) {
      /*
       * Sockets may have been closed and reopened with the
       * same FD in the signal or timeout handlers, so we
       * must skip the previous results and check again
       * whether any of the currently registered sockets have
       * events.
       */
      continue;
    }

    eloop_sock_table_dispatch(eloop, eloop->epoll_events, res);
  }

  eloop->terminate = 0;
out:
  return;
}

void eloop_terminate(struct eloop_data *eloop) {
  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return;
  }

  eloop->terminate = 1;
}

/**
 * eloop_destroy - Free any resources allocated for the event loop
 * @eloop: eloop context
 * After calling eloop_destroy(), other eloop_* functions must not be called
 * before re-running eloop_init().
 */
void eloop_destroy(struct eloop_data *eloop) {
  struct eloop_timeout *timeout, *prev;
  struct os_reltime now;

  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return;
  }

  if (eloop->epollfd == -1) {
    log_trace("eloop.epollfd is not initialized");
    return;
  }

  os_get_reltime(&now);
  dl_list_for_each_safe(timeout, prev, &eloop->timeout, struct eloop_timeout,
                        list) {
    int sec, usec;
    sec = timeout->time.sec - now.sec;
    usec = timeout->time.usec - now.usec;
    if (timeout->time.usec < now.usec) {
      sec--;
      usec += 1000000;
    }
    log_trace("ELOOP: remaining timeout: %d.%06d "
              "eloop_data=%p user_data=%p handler=%p",
              sec, usec, timeout->eloop_data, timeout->user_data,
              timeout->handler);
    eloop_remove_timeout(timeout);
  }
  eloop_sock_table_destroy(&eloop->readers);
  eloop_sock_table_destroy(&eloop->writers);
  eloop_sock_table_destroy(&eloop->exceptions);
  // os_free(eloop->signals);

  os_free(eloop->fd_table);
  os_free(eloop->epoll_events);
  close(eloop->epollfd);
}

void eloop_free(struct eloop_data *eloop) {
  if (eloop == NULL) {
    return;
  }

  eloop_destroy(eloop);
  os_free(eloop);
}

int eloop_terminated(struct eloop_data *eloop) {
  if (eloop == NULL) {
    log_error("eloop param is NULL");
    return -1;
  }

  return eloop->terminate /*|| eloop->pending_terminate*/;
}

void eloop_wait_for_read_sock(int sock) {
  /*
   * We can use epoll() here. But epoll() requres 4 system calls.
   * epoll_create1(), epoll_ctl() for ADD, epoll_wait, and close() for
   * epoll fd. So select() is better for performance here.
   */
  fd_set rfds;

  if (sock < 0)
    return;

  FD_ZERO(&rfds);
  FD_SET(sock, &rfds);
  select(sock + 1, &rfds, NULL, NULL, NULL);
}
