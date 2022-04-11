---
slug: capture
title: Network Capture
---

## The Network Capture architecture

The network capture has the purpose of monitoring network traffic for each connected device. The resulting traffic analytics is sent to the network controller for device management. The network capture contains the following services:

- Packet decoder
- Packet capture
- SQLite header storer
- Raw packet storer
- Device monitoring

The capture service is implemented as a standalone executable that can be run on demand by the network controller. The configuration of the capture service is depicted below:

```c
struct capture_conf {
  char capture_interface[IFNAMSIZ];
  bool promiscuous;
  bool immediate;
  uint16_t buffer_timeout;
  uint16_t process_interval;
  bool file_write;
  bool db_write;
  bool db_sync;
  char db_path[MAX_OS_PATH_LEN];
  char db_sync_address[MAX_WEB_PATH_LEN];
  uint16_t db_sync_port;
  char *filter;
};
```

The capture service can be run on a given network interface with a given filter. The capture also has the ability to store the processed packet in SQLite databases or raw format. The databases can be synchronised with the cloud for remote access.

## Packet decoder

The packet decoder extract the metadata from captured packet. The below structure represents all the protocols that are currently being decoded:

```c
struct capture_packet {
  struct ether_header *ethh;
  struct ether_arp *arph;
  struct ip *ip4h;
  struct ip6_hdr *ip6h;
  struct tcphdr *tcph;
  struct udphdr *udph;
  struct icmphdr *icmp4h;
  struct icmp6_hdr *icmp6h;
  struct dns_header *dnsh;
  struct mdns_header *mdnsh;
  struct dhcp_header *dhcph;
  uint64_t timestamp;
  uint32_t caplen;
  uint32_t length;
  uint32_t ethh_hash;
  uint32_t arph_hash;
  uint32_t ip4h_hash;
  uint32_t ip6h_hash;
  uint32_t tcph_hash;
  uint32_t udph_hash;
  uint32_t icmp4h_hash;
  uint32_t icmp6h_hash;
  uint32_t dnsh_hash;
  uint32_t mdnsh_hash;
  uint32_t dhcph_hash;
  int count;
};
```

For each decoded packet the service stores the hash of the header as well as the timestamp.

## Packet capture

The packet capture implements the actual network sniffing process. Currently it uses pcap library. But it also allow interfacing with PF_RING module that implements zero-copy technique.

## SQLite storer

The SQLite storer implements the storage process for packet metadata into sqlite databases. Below is the list of schemas created by the SQLite storer that can be used by any application to query the packets:

```
CREATE TABLE eth (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, ether_dhost TEXT, ether_shost TEXT, ether_type INTEGER,PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE arp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, arp_hrd INTEGER, arp_pro INTEGER, arp_hln INTEGER, arp_pln INTEGER, arp_op INTEGER, arp_sha TEXT, arp_spa TEXT, arp_tha TEXT, arp_tpa TEXT, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE ip4 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, ip_hl INTEGER, ip_v INTEGER, ip_tos INTEGER, ip_len INTEGER, ip_id INTEGER, ip_off INTEGER, ip_ttl INTEGER, ip_p INTEGER, ip_sum INTEGER, ip_src TEXT, ip_dst TEXT, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE ip6 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, ip6_un1_flow INTEGER, ip6_un1_plen INTEGER, ip6_un1_nxt INTEGER, cip6_un1_hlim INTEGER, ip6_un2_vfc INTEGER, ip6_src TEXT, ip6_dst TEXT, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE tcp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, source INTEGER, dest INTEGER, seq INTEGER, ack_seq INTEGER, res1 INTEGER, doff INTEGER, fin INTEGER, syn INTEGER, rst INTEGER, psh INTEGER, ack INTEGER, urg INTEGER, window INTEGER, check_p INTEGER, urg_ptr INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE udp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, source INTEGER, dest INTEGER, len INTEGER, check_p INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE icmp4 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, type INTEGER, code INTEGER, checksum INTEGER, gateway INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE icmp6 (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, icmp6_type INTEGER, icmp6_code INTEGER, icmp6_cksum INTEGER, icmp6_un_data32 INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE dns (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, tid INTEGER, flags INTEGER, nqueries INTEGER, nanswers INTEGER, nauth INTEGER, nother INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE mdns (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, tid INTEGER, flags INTEGER, nqueries INTEGER, nanswers INTEGER, nauth INTEGER, nother INTEGER, PRIMARY KEY (hash, timestamp, ethh_hash))
CREATE TABLE dhcp (hash INTEGER NOT NULL, timestamp INTEGER NOT NULL, ethh_hash INTEGER NOT NULL, caplen INTEGER, length INTEGER, op INTEGER, htype INTEGER, hlen INTEGER, hops INTEGER, xid INTEGER, secs INTEGER, flags INTEGER, ciaddr TEXT, yiaddr TEXT, siaddr TEXT, giaddr TEXT, PRIMARY KEY (hash, timestamp, ethh_hash))
```

Ever column in the respective table contains the hash of the Ethernet protocol that encapsulated the upper layers of the internet protocol suite as well as the capture timestamp.

## Raw packet storer

The raw packet storer stores the raw packet into pcap files and the metadata for each file is stored in a SQLite database. The file name for each packet is randomly generate and subsequently the name is stored in a SQLite database together with the timestamp and packet length. The schema for the SQLite database is depicted below:

```
CREATE TABLE meta (id TEXT, timestamp INTEGER NOT NULL, name TEXT, interface TEXT, filter TEXT, caplen INTEGER, length INTEGER, PRIMARY KEY (id, timestamp, interface))
```

## Device monitoring

The device monitoring service decodes the network traffic and assembles nettwork flow. Each flow is denoted by a source and destination MAC address, and protcol type. For each flow the device monitoring service calculates a fingerpint using the SHA256 algorithm.

The flow results in the following structure:

```c
struct nDPI_flow_meta {
  char src_mac_addr[MACSTR_LEN];
  char dst_mac_addr[MACSTR_LEN];
  char protocol[MAX_PROTOCOL_NAME_LEN];
  char hash[SHA256_HASH_LEN];
  char query[MAX_QUERY_LEN];
};
```

where **src_mac_addr** is the source MAC address, **dst_mac_addr** is the destination MAC address, **protocol** is the ID of the identified network protocol, **hash** is the fingerprint of the flow and **query** is the optional query string. The optional **query** string is dependent on the protocol type. For DNS, mDNS and TLS it is the same as the requested host name.

Each flow is stored in a sqlite database with teh followinf schema:

```
CREATE TABLE fingerprint (mac TEXT NOT NULL, protocol TEXT, fingerprint TEXT, timestamp INTEGER NOT NULL, query TEXT, PRIMARY KEY (mac, timestamp));
```

The timestamp is given as 64 bit microseconds value and the fingerprint string is encoded in base64.

An example of the fingerprint table rows are below:

| MAC               | PROTOCOL    | FINGERPRINT                                 | TIMESTAMP        | QUERY                 |
| ----------------- | ----------- | ------------------------------------------- | ---------------- | --------------------- |
| 84:e3:42:3a:cb:2f | TLS.Amazon  | mI1ENXMPBQDVjwGh/o0bLSrD8+O2O5RCFQLbUVt4lzI | 1625055051481102 | a2.tuyaeu.com         |
| 9c:ef:d5:fd:db:56 | TLS.Amazon  | mI1ENXMPBQDVjwGh/o0bLSrD8+O2O5RCFQLbUVt4lzI | 1625055051481102 | a2.tuyaeu.com         |
| 84:e3:42:3a:cb:2f | DNS         | NqRTRWiNdfG4zMkiXE9P0eRQIefPgMYV/vXUymxdvNw | 1625055072748967 | 1.0.0.10.in-addr.arpa |
| 9c:ef:d5:fd:db:56 | DNS         | NqRTRWiNdfG4zMkiXE9P0eRQIefPgMYV/vXUymxdvNw | 1625055072748967 | 1.0.0.10.in-addr.arpa |

The entries of the fingerprint table can be queried using the supervisor service.

For instance to retrieve all fingerprints for the MAC address 84:e3:42:3a:cb:2f one could use the following command:

```
QUERY_FINGERPRINT 84:e3:42:3a:cb:2f 0 >= all
```

To retrieve all the fingerprints up to a given timestamp one could use the following command:

```
QUERY_FINGERPRINT 84:e3:42:3a:cb:2f 1625055051481102 <= all
```

To retrieve all the fingerprints for the DNS protocol one could use the following command:

```
QUERY_FINGERPRINT 84:e3:42:3a:cb:2f 0 >= DNS
```
