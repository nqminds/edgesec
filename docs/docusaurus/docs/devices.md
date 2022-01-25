---
slug: devices
title: Supported Devices
---

The EDGESec toolset was tested on the following devices:

- Raspberry Pi 3 B+
- Raspberry Pi 4 B
- [PCengines apu2 platform](https://www.pcengines.ch/apu2.htm)
- [NVIDIA Jetson Nano](https://developer.nvidia.com/embedded/jetson-nano-developer-kit)

The compatible WiFi modems:

- [USB Wifi Adapter for the Raspberry Pi](https://thepihut.com/products/usb-wifi-adapter-for-the-raspberry-pi)
- Panda Wireless PAU09 N600 Dual Band WiFi adapter
- Compex WLE200NX 802.11a/b/g/n miniPCI express wireless card
- Compex WLE600VX 802.11ac miniPCI express wireless card

The compatible hardware secure storage modules:

- [ZYMKEY4i](https://www.zymbit.com/zymkey/) Raspberry Pi and Jetson Nano module

### Known Unsupported USB WiFi Modems

EDGESec relies on VLAN tagging to separate the network into individual subnets,
allowing control of communication between devices on separate subnets
(see [Network Control](./control.md)).

Many USB WiFi modems do not support Linux, let alone VLAN tagging.

Below is a list of known unsupported USB WiFi modems.

| Device          | USB ID                                                                    | Failure Reason   | Discussion Link                                     |
| :-------------- | :------------------------------------------------------------------------ | :--------------- | :-------------------------------------------------- |
| Ai-600          | `ID 0bda:c811 Realtek Semiconductor Corp. 802.11ac NIC`                   | No Linux Drivers | [#87](https://github.com/nqminds/EDGESec/issues/87) |
| WT-AC1686       | `ID 0bda:b812 Realtek Semiconductor Corp. RTL88x2bu [AC1200 Techkey]`     | No VLAN Tagging  | [#88](https://github.com/nqminds/EDGESec/issues/88) |
| Archer T2U Nano | `ID 2357:011e TP-Link AC600 wireless Realtek RTL8811AU [Archer T2U Nano]` | No VLAN Tagging  | [#89](https://github.com/nqminds/EDGESec/issues/89) |
| TL-WN823N       | `ID 2357:0109 TP-Link TL-WN823N v2/v3 [Realtek RTL8192EU]`                | No VLAN Tagging  | [#90](https://github.com/nqminds/EDGESec/issues/90) |
| AC1200 Techkey  | `ID 0bda:b812 Realtek Semiconductor Corp. RTL88x2bu [AC1200 Techkey]`     | No VLAN Tagging  | [#91](https://github.com/nqminds/EDGESec/issues/91) |
