uci set firewall.br0=zone
uci set firewall.br0.enabled='1'
uci set firewall.br0.name='br0'
uci delete firewall.br0.network
uci add_list firewall.br0.network="br0"
uci set firewall.br0.input='REJECT'
uci set firewall.br0.forward='REJECT'
uci set firewall.br0.output='ACCEPT'

uci set firewall.br1=zone
uci set firewall.br1.enabled='1'
uci set firewall.br1.name='br1'
uci delete firewall.br1.network
uci add_list firewall.br1.network="br1"
uci set firewall.br1.input='REJECT'
uci set firewall.br1.forward='REJECT'
uci set firewall.br1.output='ACCEPT'

uci set firewall.br2=zone
uci set firewall.br2.enabled='1'
uci set firewall.br2.name='br2'
uci delete firewall.br2.network
uci add_list firewall.br2.network="br2"
uci set firewall.br2.input='REJECT'
uci set firewall.br2.forward='REJECT'
uci set firewall.br2.output='ACCEPT'

uci set firewall.br3=zone
uci set firewall.br3.enabled='1'
uci set firewall.br3.name='br3'
uci delete firewall.br3.network
uci add_list firewall.br3.network="br3"
uci set firewall.br3.input='REJECT'
uci set firewall.br3.forward='REJECT'
uci set firewall.br3.output='ACCEPT'

uci set firewall.br4=zone
uci set firewall.br4.enabled='1'
uci set firewall.br4.name='br4'
uci delete firewall.br4.network
uci add_list firewall.br4.network="br4"
uci set firewall.br4.input='REJECT'
uci set firewall.br4.forward='REJECT'
uci set firewall.br4.output='ACCEPT'

uci set firewall.br5=zone
uci set firewall.br5.enabled='1'
uci set firewall.br5.name='br5'
uci delete firewall.br5.network
uci add_list firewall.br5.network="br5"
uci set firewall.br5.input='REJECT'
uci set firewall.br5.forward='REJECT'
uci set firewall.br5.output='ACCEPT'

uci set firewall.br6=zone
uci set firewall.br6.enabled='1'
uci set firewall.br6.name='br6'
uci delete firewall.br6.network
uci add_list firewall.br6.network="br6"
uci set firewall.br6.input='REJECT'
uci set firewall.br6.forward='REJECT'
uci set firewall.br6.output='ACCEPT'

uci set firewall.br7=zone
uci set firewall.br7.enabled='1'
uci set firewall.br7.name='br7'
uci delete firewall.br7.network
uci add_list firewall.br7.network="br7"
uci set firewall.br7.input='REJECT'
uci set firewall.br7.forward='REJECT'
uci set firewall.br7.output='ACCEPT'

uci set firewall.br8=zone
uci set firewall.br8.enabled='1'
uci set firewall.br8.name='br8'
uci delete firewall.br8.network
uci add_list firewall.br8.network="br8"
uci set firewall.br8.input='REJECT'
uci set firewall.br8.forward='REJECT'
uci set firewall.br8.output='ACCEPT'

uci set firewall.br9=zone
uci set firewall.br9.enabled='1'
uci set firewall.br9.name='br9'
uci delete firewall.br9.network
uci add_list firewall.br9.network="br9"
uci set firewall.br9.input='REJECT'
uci set firewall.br9.forward='REJECT'
uci set firewall.br9.output='ACCEPT'

uci set firewall.br10=zone
uci set firewall.br10.enabled='1'
uci set firewall.br10.name='br10'
uci delete firewall.br10.network
uci add_list firewall.br10.network="br10"
uci set firewall.br10.input='REJECT'
uci set firewall.br10.forward='REJECT'
uci set firewall.br10.output='ACCEPT'

uci set firewall.br3_ping=rule
uci set firewall.br3_ping.name='br3 Allow-Ping'
uci set firewall.br3_ping.src='br3'
uci set firewall.br3_ping.proto='icmp'
uci set firewall.br3_ping.icmp_type='echo-request'
uci set firewall.br3_ping.family='ipv4'
uci set firewall.br3_ping.target='ACCEPT'

uci set firewall.br5_ping=rule
uci set firewall.br5_ping.name='br5 Allow-Ping'
uci set firewall.br5_ping.src='br5'
uci set firewall.br5_ping.proto='icmp'
uci set firewall.br5_ping.icmp_type='echo-request'
uci set firewall.br5_ping.family='ipv4'
uci set firewall.br5_ping.target='ACCEPT'

uci set firewall.br7_ping=rule
uci set firewall.br7_ping.name='br7 Allow-Ping'
uci set firewall.br7_ping.src='br7'
uci set firewall.br7_ping.proto='icmp'
uci set firewall.br7_ping.icmp_type='echo-request'
uci set firewall.br7_ping.family='ipv4'
uci set firewall.br7_ping.target='ACCEPT'

uci set firewall.br9_ping=rule
uci set firewall.br9_ping.name='br9 Allow-Ping'
uci set firewall.br9_ping.src='br9'
uci set firewall.br9_ping.proto='icmp'
uci set firewall.br9_ping.icmp_type='echo-request'
uci set firewall.br9_ping.family='ipv4'
uci set firewall.br9_ping.target='ACCEPT'

uci set firewall.br5_dns_rule=rule
uci set firewall.br5_dns_rule.enabled='1'
uci set firewall.br5_dns_rule.name='br5 dns rule'
uci set firewall.br5_dns_rule.src='br5'
uci set firewall.br5_dns_rule.proto='tcpudp'
uci set firewall.br5_dns_rule.dest_port='53'
uci set firewall.br5_dns_rule.target='ACCEPT'

uci set firewall.br5_dhcp_rule=rule
uci set firewall.br5_dhcp_rule.enabled='1'
uci set firewall.br5_dhcp_rule.name='br5 dhcp rule'
uci set firewall.br5_dhcp_rule.src='br5'
uci set firewall.br5_dhcp_rule.proto='udp'
uci set firewall.br5_dhcp_rule.src_port='67-68'
uci set firewall.br5_dhcp_rule.dest_port='67-68'
uci set firewall.br5_dhcp_rule.target='ACCEPT'

uci set firewall.br5_Allow_DHCPv6=rule
uci set firewall.br5_Allow_DHCPv6.enabled='1'
uci set firewall.br5_Allow_DHCPv6.name='br5 dhcp6 rule'
uci set firewall.br5_Allow_DHCPv6.src='br5'
uci set firewall.br5_Allow_DHCPv6.proto='udp'
uci set firewall.br5_Allow_DHCPv6.src_ip='fe80::/10'
uci set firewall.br5_Allow_DHCPv6.src_port='546-547'
uci set firewall.br5_Allow_DHCPv6.dest_ip='fe80::/10'
uci set firewall.br5_Allow_DHCPv6.dest_port='546-547'
uci set firewall.br5_Allow_DHCPv6.family='ipv6'
uci set firewall.br5_Allow_DHCPv6.target='ACCEPT'

uci set firewall.br7_dns_rule=rule
uci set firewall.br7_dns_rule.enabled='1'
uci set firewall.br7_dns_rule.name='br7 dns rule'
uci set firewall.br7_dns_rule.src='br7'
uci set firewall.br7_dns_rule.proto='tcpudp'
uci set firewall.br7_dns_rule.dest_port='53'
uci set firewall.br7_dns_rule.target='ACCEPT'

uci set firewall.br7_dhcp_rule=rule
uci set firewall.br7_dhcp_rule.enabled='1'
uci set firewall.br7_dhcp_rule.name='br7 dhcp rule'
uci set firewall.br7_dhcp_rule.src='br7'
uci set firewall.br7_dhcp_rule.proto='udp'
uci set firewall.br7_dhcp_rule.src_port='67-68'
uci set firewall.br7_dhcp_rule.dest_port='67-68'
uci set firewall.br7_dhcp_rule.target='ACCEPT'

uci set firewall.br7_Allow_DHCPv6=rule
uci set firewall.br7_Allow_DHCPv6.enabled='1'
uci set firewall.br7_Allow_DHCPv6.name='br7 dhcp6 rule'
uci set firewall.br7_Allow_DHCPv6.src='br7'
uci set firewall.br7_Allow_DHCPv6.proto='udp'
uci set firewall.br7_Allow_DHCPv6.src_ip='fe80::/10'
uci set firewall.br7_Allow_DHCPv6.src_port='546-547'
uci set firewall.br7_Allow_DHCPv6.dest_ip='fe80::/10'
uci set firewall.br7_Allow_DHCPv6.dest_port='546-547'
uci set firewall.br7_Allow_DHCPv6.family='ipv6'
uci set firewall.br7_Allow_DHCPv6.target='ACCEPT'

uci set firewall.br9_dns_rule=rule
uci set firewall.br9_dns_rule.enabled='1'
uci set firewall.br9_dns_rule.name='br9 dns rule'
uci set firewall.br9_dns_rule.src='br9'
uci set firewall.br9_dns_rule.proto='tcpudp'
uci set firewall.br9_dns_rule.dest_port='53'
uci set firewall.br9_dns_rule.target='ACCEPT'

uci set firewall.br9_dhcp_rule=rule
uci set firewall.br9_dhcp_rule.enabled='1'
uci set firewall.br9_dhcp_rule.name='br9 dhcp rule'
uci set firewall.br9_dhcp_rule.src='br9'
uci set firewall.br9_dhcp_rule.proto='udp'
uci set firewall.br9_dhcp_rule.src_port='67-68'
uci set firewall.br9_dhcp_rule.dest_port='67-68'
uci set firewall.br9_dhcp_rule.target='ACCEPT'

uci set firewall.br9_Allow_DHCPv6=rule
uci set firewall.br9_Allow_DHCPv6.enabled='1'
uci set firewall.br9_Allow_DHCPv6.name='br9 dhcp6 rule'
uci set firewall.br9_Allow_DHCPv6.src='br9'
uci set firewall.br9_Allow_DHCPv6.proto='udp'
uci set firewall.br9_Allow_DHCPv6.src_ip='fe80::/10'
uci set firewall.br9_Allow_DHCPv6.src_port='546-547'
uci set firewall.br9_Allow_DHCPv6.dest_ip='fe80::/10'
uci set firewall.br9_Allow_DHCPv6.dest_port='546-547'
uci set firewall.br9_Allow_DHCPv6.family='ipv6'
uci set firewall.br9_Allow_DHCPv6.target='ACCEPT'

uci set firewall.1009141_1003209=rule
uci set firewall.1009141_1003209.enabled='1'
uci set firewall.1009141_1003209.name='Accept 10.0.9.141-10.0.3.209'
uci set firewall.1009141_1003209.src='br9'
uci set firewall.1009141_1003209.src_ip='10.0.9.141'
uci set firewall.1009141_1003209.dest='br3'
uci set firewall.1009141_1003209.dest_ip='10.0.3.209'
uci set firewall.1009141_1003209.proto='all'
uci set firewall.1009141_1003209.target='ACCEPT'

uci set firewall.1009140_1003209=rule
uci set firewall.1009140_1003209.enabled='1'
uci set firewall.1009140_1003209.name='Accept 10.0.9.140-10.0.3.209'
uci set firewall.1009140_1003209.src='br9'
uci set firewall.1009140_1003209.src_ip='10.0.9.140'
uci set firewall.1009140_1003209.dest='br3'
uci set firewall.1009140_1003209.dest_ip='10.0.3.209'
uci set firewall.1009140_1003209.proto='all'
uci set firewall.1009140_1003209.target='ACCEPT'

uci set firewall.1003209_1009140=rule
uci set firewall.1003209_1009140.enabled='1'
uci set firewall.1003209_1009140.name='Accept 10.0.3.209-10.0.9.140'
uci set firewall.1003209_1009140.src='br3'
uci set firewall.1003209_1009140.src_ip='10.0.3.209'
uci set firewall.1003209_1009140.dest='br9'
uci set firewall.1003209_1009140.dest_ip='10.0.9.140'
uci set firewall.1003209_1009140.proto='all'
uci set firewall.1003209_1009140.target='ACCEPT'

uci set firewall.1003209_1007191=rule
uci set firewall.1003209_1007191.enabled='1'
uci set firewall.1003209_1007191.name='Accept 10.0.3.209-10.0.7.191'
uci set firewall.1003209_1007191.src='br3'
uci set firewall.1003209_1007191.src_ip='10.0.3.209'
uci set firewall.1003209_1007191.dest='br7'
uci set firewall.1003209_1007191.dest_ip='10.0.7.191'
uci set firewall.1003209_1007191.proto='all'
uci set firewall.1003209_1007191.target='ACCEPT'

uci set firewall.1007191_1003209=rule
uci set firewall.1007191_1003209.enabled='1'
uci set firewall.1007191_1003209.name='Accept 10.0.7.191-10.0.3.209'
uci set firewall.1007191_1003209.src='br7'
uci set firewall.1007191_1003209.src_ip='10.0.7.191'
uci set firewall.1007191_1003209.dest='br3'
uci set firewall.1007191_1003209.dest_ip='10.0.3.209'
uci set firewall.1007191_1003209.proto='all'
uci set firewall.1007191_1003209.target='ACCEPT'

uci set firewall.1007191_1009141=rule
uci set firewall.1007191_1009141.enabled='1'
uci set firewall.1007191_1009141.name='Accept 10.0.7.191-10.0.9.141'
uci set firewall.1007191_1009141.src='br7'
uci set firewall.1007191_1009141.src_ip='10.0.7.191'
uci set firewall.1007191_1009141.dest='br9'
uci set firewall.1007191_1009141.dest_ip='10.0.9.141'
uci set firewall.1007191_1009141.proto='all'
uci set firewall.1007191_1009141.target='ACCEPT'

uci set firewall.1007191_1009140=rule
uci set firewall.1007191_1009140.enabled='1'
uci set firewall.1007191_1009140.name='Accept 10.0.7.191-10.0.9.140'
uci set firewall.1007191_1009140.src='br7'
uci set firewall.1007191_1009140.src_ip='10.0.7.191'
uci set firewall.1007191_1009140.dest='br9'
uci set firewall.1007191_1009140.dest_ip='10.0.9.140'
uci set firewall.1007191_1009140.proto='all'
uci set firewall.1007191_1009140.target='ACCEPT'

uci set firewall.1009140_1007191=rule
uci set firewall.1009140_1007191.enabled='1'
uci set firewall.1009140_1007191.name='Accept 10.0.9.140-10.0.7.191'
uci set firewall.1009140_1007191.src='br9'
uci set firewall.1009140_1007191.src_ip='10.0.9.140'
uci set firewall.1009140_1007191.dest='br7'
uci set firewall.1009140_1007191.dest_ip='10.0.7.191'
uci set firewall.1009140_1007191.proto='all'
uci set firewall.1009140_1007191.target='ACCEPT'

uci set firewall.1009141_dnat=redirect
uci set firewall.1009141_dnat.enabled='1'
uci set firewall.1009141_dnat.name='DNAT 10.0.9.141'
uci set firewall.1009141_dnat.src='wan'
uci set firewall.1009141_snat.src_ip='0.0.0.0'
uci set firewall.1009141_dnat.dest='br9'
uci set firewall.1009141_dnat.dest_ip='10.0.9.141'
uci set firewall.1009141_dnat.proto='all'
uci set firewall.1009141_dnat.target='DNAT'

uci set firewall.1009141_snat=redirect
uci set firewall.1009141_snat.enabled='1'
uci set firewall.1009141_snat.name='SNAT 10.0.9.141'
uci set firewall.1009141_snat.src='br9'
uci set firewall.1009141_snat.src_ip='10.0.9.141'
uci set firewall.1009141_snat.dest='wan'
uci set firewall.1009141_snat.proto='all'
uci set firewall.1009141_snat.target='SNAT'

uci set firewall.1009141_forward=rule
uci set firewall.1009141_forward.enabled='1'
uci set firewall.1009141_forward.name='Forward 10.0.9.141'
uci set firewall.1009141_forward.src='br9'
uci set firewall.1009141_forward.src_ip='10.0.9.141'
uci set firewall.1009141_forward.dest='wan'
uci set firewall.1009141_forward.proto='all'
uci set firewall.1009141_forward.target='ACCEPT'

uci set firewall.1009141_backward=rule
uci set firewall.1009141_backward.enabled='1'
uci set firewall.1009141_backward.name='Backward 10.0.9.141'
uci set firewall.1009141_backward.src='wan'
uci set firewall.1009141_backward.dest='br9'
uci set firewall.1009141_backward.dest_ip='10.0.9.141'
uci set firewall.1009141_backward.proto='all'
uci set firewall.1009141_backward.target='ACCEPT'

uci set firewall.1009140_dnat=redirect
uci set firewall.1009140_dnat.enabled='1'
uci set firewall.1009140_dnat.name='DNAT 10.0.9.140'
uci set firewall.1009140_dnat.src='wan'
uci set firewall.1009140_dnat.dest='br9'
uci set firewall.1009140_dnat.dest_ip='10.0.9.140'
uci set firewall.1009140_dnat.proto='all'
uci set firewall.1009140_dnat.target='DNAT'

uci set firewall.1009140_snat=redirect
uci set firewall.1009140_snat.enabled='1'
uci set firewall.1009140_snat.name='SNAT 10.0.9.140'
uci set firewall.1009140_snat.src='br9'
uci set firewall.1009140_snat.src_ip='10.0.9.140'
uci set firewall.1009140_snat.dest='wan'
uci set firewall.1009140_snat.proto='all'
uci set firewall.1009140_snat.target='SNAT'

uci set firewall.1009140_forward=rule
uci set firewall.1009140_forward.enabled='1'
uci set firewall.1009140_forward.name='Forward 10.0.9.140'
uci set firewall.1009140_forward.src='br9'
uci set firewall.1009140_forward.src_ip='10.0.9.140'
uci set firewall.1009140_forward.dest='wan'
uci set firewall.1009140_forward.proto='all'
uci set firewall.1009140_forward.target='ACCEPT'

uci set firewall.1009140_backward=rule
uci set firewall.1009140_backward.enabled='1'
uci set firewall.1009140_backward.name='Backward 10.0.9.140'
uci set firewall.1009140_backward.src='wan'
uci set firewall.1009140_backward.dest='br9'
uci set firewall.1009140_backward.dest_ip='10.0.9.140'
uci set firewall.1009140_backward.proto='all'
uci set firewall.1009140_backward.target='ACCEPT'

uci commit firewall
/etc/init.d/firewall reload
