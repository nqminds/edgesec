# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Create the path to sqlite db if none exist
- Terminate the eloop for capture, mdns and runctl threads
- Reload config.ini when SIGHUP
- Convert uint64_t time types to time_t
- recap tool file for instantiating the capture db from a pcap file

## [0.0.8] - 2022-07-26
### Added
- If there are no VLAN interfaces created, edgesec will try to set an IP if no IP present
- Added changelog file starting from version 0.0.8
- Compile doxygen with CI actions and added docs as iframe to [https://edgesec.info](https://edgesec.info)


### Changed
- The dnsmasq config uses three types of interfaces (bridge, interface and wifi interface) for the config
- Changed the code licence info to linux kernel style licence

### Removed
- Quarantine parameter removed from the config.ini
- Docusaurus page moved to [https://edgesec.info](https://edgesec.info) site and repo [https://github.com/nqminds/edgesec.info](https://github.com/nqminds/edgesec.info)
