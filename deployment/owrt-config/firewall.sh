uci set firewall.br0=zone
uci set firewall.br0.enabled='1'
uci set firewall.br0.name='br0'
uci delete firewall.br0.network
uci add_list firewall.br0.network="br0"
uci set firewall.br0.input='REJECT'
uci set firewall.br0.forward='REJECT'
uci set firewall.br0.output='ACCEPT'

uci commit firewall
/etc/init.d/firewall reload

