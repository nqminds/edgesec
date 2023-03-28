#include <stdlib.h>
#include <errno.h>
#include <utarray.h>

#include "../utils/net.h"
#include "../utils/os.h"

#include "./dhcp_config_utils.h"

bool get_config_dhcpinfo(char *info, config_dhcpinfo_t *el) {
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  if (split_string_array(info, ',', info_arr) < 0) {
    goto err;
  }

  if (!utarray_len(info_arr)) {
    goto err;
  }

  char **p = NULL;
  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL) {
    errno = 0;
    el->vlanid = (int)strtol(*p, NULL, 10);
    if (errno == EINVAL)
      goto err;
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL) {
    os_strlcpy(el->ip_addr_low, *p, OS_INET_ADDRSTRLEN);
  } else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->ip_addr_upp, *p, OS_INET_ADDRSTRLEN);
  else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->subnet_mask, *p, OS_INET_ADDRSTRLEN);
  else
    goto err;

  p = (char **)utarray_next(info_arr, p);
  if (*p != NULL)
    os_strlcpy(el->lease_time, *p, DHCP_LEASE_TIME_SIZE);
  else
    goto err;

  utarray_free(info_arr);
  return true;

err:
  utarray_free(info_arr);
  return false;
}
