/****************************************************************************
 * Copyright (C) 2021 by NQMCyber Ltd                                       *
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
 * @file ndpi_serialiser.c 
 * @author Alexandru Mereacre 
 * @brief File containing the implementation of the ndpi serialiser utils.
 */

#include <ndpi_api.h>
#include <ndpi_main.h>
#include <ndpi_typedefs.h>

#include "ndpi_serialiser.h"

#include "../utils/log.h"
int ndpi_serialise_sat(struct ndpi_detection_module_struct *ndpi_struct,
		  struct nDPI_flow_info * flow_info)
{
  char proto_name[64];
  char *breed_name;
  char *category_name;
  struct ndpi_proto l7_protocol = flow_info->detected_l7_protocol;
  ndpi_protocol2name(ndpi_struct, l7_protocol, proto_name, sizeof(proto_name));
  ndpi_protocol_breed_t breed = ndpi_get_proto_breed(ndpi_struct,
                           (l7_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN ? l7_protocol.app_protocol : l7_protocol.master_protocol));
  breed_name = ndpi_get_proto_breed_name(ndpi_struct, breed);
  
  if(l7_protocol.category != NDPI_PROTOCOL_CATEGORY_UNSPECIFIED)
    category_name = ndpi_category_get_name(ndpi_struct, l7_protocol.category);
  log_trace("proto=%s", proto_name);
  log_trace("breed=%s", breed_name);
  log_trace("category=%s", category_name);
  return 0;
}
