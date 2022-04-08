// Set the environment variable ENV_DB_KEY=dbpath:dbprefix
// Use SELECT load_extension("./src/libsqlhook.so"); to load the extension
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */

#include "utils/os.h"
#include "utils/utarray.h"
SQLITE_EXTENSION_INIT1

#define ENV_DB_KEY  "EDGESEC_DB"

static char db_path[MAX_OS_PATH_LEN];
static char db_prefix[MAX_OS_PATH_LEN];

void update_hook(void *data, int type, char const *database, char const *table, sqlite3_int64 rowid)
{
  (void) database;
  
  FILE *f = fopen(db_path, "a+");

  if (f == NULL) {
    return;
  }

  fprintf(f, "%d %s %lld\n", type, table, rowid);

  fclose(f);
}

int decode_env_key_value(char *kvalue)
{
  UT_array *values;
  char **p = NULL;

  utarray_new(values, &ut_str_icd);

  if (split_string_array(kvalue, ':', values) < 2) {
    utarray_free(values);
    return -1;
  }

  p = (char**) utarray_next(values, p);
  strncpy(db_path, *p, MAX_OS_PATH_LEN);

  p = (char**) utarray_next(values, p);
  strncpy(db_prefix, *p, MAX_OS_PATH_LEN);

  utarray_free(values);
  return 0;
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

  char *env_key_value;
  int rc = SQLITE_OK;
  
  SQLITE_EXTENSION_INIT2(pApi);
  
  FILE *f = fopen("/tmp/debug", "a+");
  if ((env_key_value = getenv(ENV_DB_KEY)) == NULL) {
    return rc;
  }

  if (decode_env_key_value(env_key_value) < 0) {
    return rc;
  }

  fprintf(f, "%s %s\n", db_path, db_prefix);
  //sqlite3_update_hook(db, update_hook, NULL);
  
  fclose(f);
  return rc;
}