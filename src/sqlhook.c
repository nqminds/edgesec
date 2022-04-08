#include <stdio.h>
#include <stdlib.h>
#include <sqlite3ext.h> /* Do not use <sqlite3.h>! */
SQLITE_EXTENSION_INIT1

#define ENV_DB_KEY  "EDGESEC_DB"

void update_hook(void *data, int type, char const *database, char const *table, sqlite3_int64 rowid)
{
  (void) database;
  char *db_path = NULL;

  if ((db_path = getenv(ENV_DB_KEY)) == NULL) {
    return;
  }

  FILE *f = fopen(db_path, "a+");

  if (f == NULL) {
    return;
  }

  fprintf(f, "%d %s %lld\n", type, table, rowid);

  fclose(f);
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

  int rc = SQLITE_OK;
  SQLITE_EXTENSION_INIT2(pApi);
  
  sqlite3_update_hook(db, update_hook, NULL);

  return rc;
}