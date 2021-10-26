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
 * @brief File containing the implementation of the request utils functionalities.
 */
#include <stdlib.h>
#include <string.h>

#include "curl_utils.h"
#include "base64.h"
#include "log.h"

#define RESPONSE_KEY "\"response\":"
int process_request(char *request, char **out)
{
  size_t out_size;
  char *ptr = NULL, *end = NULL;
  *out = NULL;

  if((ptr = strstr(request, RESPONSE_KEY)) == NULL) {
    log_trace("No %s key found", RESPONSE_KEY);
    return -1;
  }

  ptr += strlen(RESPONSE_KEY) + 1;

  if((ptr = strstr(ptr, "\"")) == NULL) {
    log_trace("No beginning \" found", RESPONSE_KEY);
    return -1;
  }

  if((end = strstr(ptr + 1, "\"")) == NULL) {
    log_trace("No end \" found", RESPONSE_KEY);
    return -1;
  }
  
  out_size = end - ptr;
  *out = malloc(out_size + 1);
  memset(*out, 0, out_size + 1);
  memcpy(*out, ptr + 1, out_size);

  return 0;
}

char* get_response_base64_str(char *url)
{
  char *req_data = NULL;
  char *response_base64 = NULL;

  if (get_url_data(url, &req_data) < 0) {
    log_trace("get_url_data fail");
    return NULL;
  }

  if (process_request(req_data, &response_base64) < 0) {
    log_trace("process_request fail");
    free(req_data);
    return NULL;
  }

  if (strcmp(response_base64, "FAIL") == 0) {
    log_trace("FAIL response");
    free(req_data);
    free(response_base64);
    return NULL;
  }

  free(req_data);
  return response_base64;
}

ssize_t get_response(char *url, unsigned char **out)
{
  char *response_base64 = NULL;
  size_t response_len;

  log_trace("get_reponse call");

  *out = NULL;
  if ((response_base64 = get_response_base64_str(url)) == NULL) {
    log_trace("get_response_str fail");
    return -1;
  }

  if ((*out = (unsigned char *)base64_url_decode((unsigned char *)response_base64, strlen(response_base64), &response_len)) == NULL) {
    log_trace("base64_url_decode fail");
    free(response_base64);  
    return -1;
  }

  free(response_base64);
  return (ssize_t)response_len;
}

char* get_response_str(char *url)
{
  char *response_base64 = NULL;
  char *response = NULL;
  size_t response_len;

  log_trace("get_reponse call");

  if ((response_base64 = get_response_base64_str(url)) == NULL) {
    log_trace("get_response_str fail");
    return NULL;
  }

  if ((response = (char *)base64_url_decode((unsigned char *)response_base64, strlen(response_base64), &response_len)) == NULL) {
    log_trace("base64_url_decode fail");
    free(response_base64);
    return NULL;  
  }

  free(response_base64);
  return response;
}

int confirm_reponse(char *url)
{
  char* response = get_response_base64_str(url);

  if (response == NULL) {
    log_trace("get_response_str fail");
    return -1;
  }

  if (strcmp(response, "OK") != 0) {
    log_trace("Non OK response");
    free(response);
    return -1;
  }

  free(response);
  return 0;
}
