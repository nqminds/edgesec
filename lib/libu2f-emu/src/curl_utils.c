/****************************************************************************
 * Copyright (C) 2020 by NQMCyber Ltd                                       *
 *                                                                          *
 * This file is part of EDGESec.                                            *
 *                                                                          *
 *   EDGESec is free software: you can redistribute it and/or modify it     *
 *   under the terms of the GNU Lesser General Public License as published  *
 *   by the Free Software Foundation, either version 3 of the License, or   *
 *   (at your option) any later version.                                    *
 *                                                                          *
 *   EDGESec is distributed in the hope that it will be useful,             *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of         *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          *
 *   GNU Lesser General Public License for more details.                    *
 *                                                                          *
 *   You should have received a copy of the GNU Lesser General Public       *
 *   License along with EDGESec. If not, see <http://www.gnu.org/licenses/>.*
 ****************************************************************************/

/**
 * @file curl_utils.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the curl utils functionalities.
 */
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "log.h"

struct memory_output {
  char *memory;
  size_t size;
};

static size_t write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct memory_output *mem = (struct memory_output *)userp;
 
  char *ptr = realloc(mem->memory, mem->size + realsize + 1);

  if(ptr == NULL) {
    log_err("realloc");
    return 0;
  }
 
  mem->memory = ptr;
  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;
 
  return realsize;
}

int get_url_data(char *url, char **out)
{
  (void) out;

  CURL *curl;
  CURLcode res;
  struct memory_output chunk;

  chunk.memory = malloc(1);
  chunk.size = 0;

  curl = curl_easy_init();
  if (curl != NULL) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK) {
      log_trace("curl_easy_perform() failed: %s", curl_easy_strerror(res));
      free(chunk.memory);
      curl_easy_cleanup(curl);
      curl_global_cleanup();
      return -1;  
    }

    log_trace("Received %lu bytes", (unsigned long)chunk.size);
    *out = malloc(chunk.size + 1);
    memset(*out, 0, chunk.size + 1);
    memcpy(*out, chunk.memory, chunk.size);
  } else {
    log_trace("curl_easy_init fail");
    free(chunk.memory);
    curl_global_cleanup();
    return -1;
  }

  free(chunk.memory);
  curl_easy_cleanup(curl);
  curl_global_cleanup();
  return 0;
}