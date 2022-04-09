// Set the environment variable ENV_DB_KEY=dbpath:dbprefix
// Use SELECT load_extension("./src/libsqlhook.so"); to load the extension
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */

#include "utils/os.h"
#include "utils/utarray.h"
SQLITE_EXTENSION_INIT1

#define ENV_DB_KEY  "EDGESEC_DB"
#define DOMAIN_ID_STR   "domain"
#define DELIMITER_CHAR  '_'

struct dir_ctx {
  UT_array *domain_sockets;
  UT_array *ports;
};

static char sock_path[MAX_OS_PATH_LEN];

void update_hook(void *data, int type, char const *database, char const *table, sqlite3_int64 rowid)
{
  (void) database;
  
  FILE *f = fopen(sock_path, "a+");

  if (f == NULL) {
    return;
  }

  fprintf(f, "%d %s %lld\n", type, table, rowid);

  fclose(f);
}

bool list_dir_function(char *path, void *args)
{
  struct dir_ctx *ctx = (struct dir_ctx*) args;
  char *filename, *del, port_str[6];
  int port;
  FILE *f = fopen("/tmp/debug", "a+");

  if (strstr(path, SOCK_EXTENSION)) {
    if ((filename = basename(path)) != NULL) {
      if (strstr(filename, DOMAIN_ID_STR)) {
        utarray_push_back(ctx->domain_sockets, &filename);
        fprintf(f, "%s\n", path);
      } else {
        if ((del = strchr(filename, DELIMITER_CHAR)) != NULL) {
          port = (int)(del - filename);
          if (port > 0 && port < 6) {
            os_memcpy(port_str, filename, port);
            port_str[port] = '\0';

            errno = 0;
            port = (int) strtol(port_str, NULL, 10);
            if (errno != EINVAL) {
              fprintf(f, "%d\n", port);
            }
          }
        }
      }
    }
  }

  fclose(f);
  return true;
}

#ifdef _WIN32
__declspec(dllexport)
#endif
/* TODO: Change the entry point name so that "extension" is replaced by
** text derived from the shared library filename as follows:  Copy every
** ASCII alphabetic character from the filename after the last "/" through
** the next following ".", converting each character to lowercase, and
** discarding the first three characters if they are "lib".
*/
int sqlite3_extension_init(
  sqlite3 *db, 
  char **pzErrMsg, 
  const sqlite3_api_routines *pApi
){
  (void) pzErrMsg;

  struct dir_ctx ctx = {NULL, NULL};
  char *env_key_value;
  int rc = SQLITE_OK;
  
  SQLITE_EXTENSION_INIT2(pApi);
  
  if ((env_key_value = getenv(ENV_DB_KEY)) == NULL) {
    return rc;
  }

  strncpy(sock_path, env_key_value, MAX_OS_PATH_LEN);
  
  utarray_new(ctx.domain_sockets, &ut_str_icd);

  if (list_dir(sock_path, list_dir_function, (void *)&ctx) < 0) {
    utarray_free(ctx.domain_sockets);
    return rc;
  }
  //sqlite3_update_hook(db, update_hook, NULL);

  utarray_free(ctx.domain_sockets);
  return rc;
}