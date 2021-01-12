/**************************************************************************************************
*  Filename:        domain_server.h
*  Author:          Alexandru Mereacre (mereacre@gmail.com)
*  Revised:
*  Revision:
*
*  Description:     domain_server include file
*
*  Copyright (C) 2020 NQMCyber Ltd - http://www.nqmcyber.com/
*************************************************************************************************/

#ifndef DOMAIN_SERVER_H
#define DOMAIN_SERVER_H

#include <sys/types.h>

int create_domain_server(char *server_path);
ssize_t read_domain_data(int sock, char *data, size_t data_len, char *addr);
ssize_t write_domain_data(int sock, char *data, size_t data_len, char *addr);

#endif