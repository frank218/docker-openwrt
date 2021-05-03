config globals globals
    option 'ula_prefix' 'auto'

config 'interface'    'loopback'
    option 'ifname'   'lo'
    option 'proto'    'static'
    option 'ipaddr'   '127.0.0.1'
    option 'netmask'  '255.0.0.0'
 
config 'interface'    'lan'
    option 'ifname'   "${LAN_PARENT}"
    option 'proto'    'static'
    option 'ipaddr'   "${LAN_ADDR}"
    option 'gateway'  "${LAN_GW}"
    option 'netmask'  "${LAN_NETMASK}"
    option 'ip6assign' 64

config 'interface'    'aux'
    option 'ifname'   "${AUX_PARENT}"
    option 'proto'    'static'
    option 'ipaddr'   "${AUX_ADDR}"
    option 'gateway'  "${AUX_GW}"
    option 'netmask'  "${AUX_NETMASK}"
    option 'ip6assign' 64

config 'interface'    'docker'
    option 'ifname'   "${INT_IFNAME}"
    option 'proto'    'dhcp'

config 'interface'    'wan'
    option 'ifname'   'enp4s0'
    option 'proto'    'dhcp'

config 'interface'    'wan6'
    option 'ifname'   'enp4s0'
    option 'proto'    'dhcpv6'
