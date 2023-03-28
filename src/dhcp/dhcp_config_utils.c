#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <utarray.h>

#include "../utils/net.h"
#include "../utils/os.h"

#include "./dhcp_config_utils.h"

bool get_config_dhcpinfo(const char *info, config_dhcpinfo_t *el) {
  UT_array *info_arr;
  utarray_new(info_arr, &ut_str_icd);

  ssize_t substrings = split_string_array(info, ',', info_arr);
  if (substrings < 5) {
    log_error("get_config_dhcpinfo: Expected 5 comma-separated substrings but "
              "got %ld in string %s",
              substrings, info);
    goto err;
  }

  char **vlanid_string = utarray_eltptr(info_arr, 0);
  char **ip_addr_low = utarray_eltptr(info_arr, 1);
  char **ip_addr_upp = utarray_eltptr(info_arr, 2);
  char **subnet_mask = utarray_eltptr(info_arr, 3);
  char **lease_time = utarray_eltptr(info_arr, 4);

  errno = 0;
  long vlanid_long = strtol(*vlanid_string, NULL, 10);
  if (errno == 0 && vlanid_long > UINT_MAX) {
    errno = ERANGE;
  }
  *el = (config_dhcpinfo_t){
      .vlanid = (int)vlanid_long,
  };
  if (errno) {
    log_errno("get_config_dhcpinfo: Failed to convert vlanid: %s to an integer",
              *vlanid_string);
    goto err;
  }

  os_strlcpy(el->ip_addr_low, *ip_addr_low, OS_INET_ADDRSTRLEN);
  os_strlcpy(el->ip_addr_upp, *ip_addr_upp, OS_INET_ADDRSTRLEN);
  os_strlcpy(el->subnet_mask, *subnet_mask, OS_INET_ADDRSTRLEN);
  os_strlcpy(el->lease_time, *lease_time, DHCP_LEASE_TIME_SIZE);

  utarray_free(info_arr);
  return true;
err:
  utarray_free(info_arr);
  return false;
}
