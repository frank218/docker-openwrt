#!/usr/bin/env bash
# set -x

_usage() {
	echo "Could not find config file."
	echo "Usage: $0 [/path/to/openwrt.conf]"
	exit 1
}

SCRIPT_DIR=$(cd $(dirname $0) && pwd )
DEFAULT_CONFIG_FILE=$SCRIPT_DIR/openwrt.conf
CONFIG_FILE=${1:-$DEFAULT_CONFIG_FILE}
source $CONFIG_FILE 2>/dev/null || { _usage; exit 1; }

_nmcli() {
	type nmcli >/dev/null 2>&1
	if [[ $? -eq 0 ]]; then
		echo "* setting interface '$WIFI_IFACE' to unmanaged"
		nmcli dev set $WIFI_IFACE managed no
		nmcli radio wifi on
	fi
}

_get_phy_from_dev() {
	test $WIFI_ENABLED = 'true' || return
	test -z $WIFI_PHY || return
	if [[ -f /sys/class/net/$WIFI_IFACE/phy80211/name ]]; then
		WIFI_PHY=$(cat /sys/class/net/$WIFI_IFACE/phy80211/name 2>/dev/null)
		echo "* got '$WIFI_PHY' for device '$WIFI_IFACE'"
	else
		echo "$WIFI_IFACE is not a valid phy80211 device"
		exit 1
	fi
}

_cleanup() {
	echo -e "\n* cleaning up..."
	echo "* stopping container"
	docker stop $CONTAINER >/dev/null
	echo "* cleaning up netns symlink"
	sudo rm -rf /var/run/netns/$CONTAINER
	if [[ $LAN_DRIVER != "direct" ]] ; then
		echo "* removing host $LAN_DRIVER interface"
		if [[ $LAN_DRIVER != "bridge" ]] ; then
			sudo ip link del dev $LAN_IFACE
		elif [[ $LAN_PARENT =~ \. ]] ; then
			sudo ip link del dev $LAN_PARENT
		fi
	fi
	echo -ne "* finished"
}

_gen_config() {
	echo "* generating OpenWRT config"
	set -a
	_get_phy_from_dev
	source $CONFIG_FILE
	for file in etc/config/*.tpl; do
		envsubst <${file} >${file%.tpl}
		docker cp ${file%.tpl} $CONTAINER:/${file%.tpl}
	done
	set +a
}

_init_network() {
	if [[ "${LAN_DRIVER}" != "direct" ]] ; then
		echo "* setting up docker network for LAN"
		local LAN_ARGS
		case $LAN_DRIVER in
			bridge)
				LAN_ARGS=""
			;;
			macvlan)
				LAN_ARGS="-o parent=$LAN_PARENT"
			;;
			ipvlan)
				LAN_ARGS="-o parent=$LAN_PARENT -o ipvlan_mode=l2"
			;;
			*)
				echo "invalid choice for LAN network driver"
				exit 1
			;;
		esac
		docker network create --driver $LAN_DRIVER \
			$LAN_ARGS \
			--subnet $LAN_SUBNET \
			$LAN_NAME || exit 1
	fi

	if [[ ${INT_NAME} ]] && [[ "${INT_NAME}" != "bridge" ]] ; then
		echo "* setting up docker network for internal communication"
		docker network create --driver bridge \
			--subnet $INT_SUBNET \
			--internal \
			$INT_NAME || exit 1
	fi

	if [[ "${WAN_DRIVER}" != "direct" ]] ; then
		echo "* setting up docker network for WAN"
		docker network create --driver $WAN_DRIVER \
			-o parent=$WAN_PARENT \
			$WAN_NAME || exit 1
	fi
}

_set_hairpin() {
	test $WIFI_HAIRPIN = 'true' || return
	echo -n "* set hairpin mode on interface '$1'"
	for i in {1..10}; do
		echo -n '.'
		sudo ip netns exec $CONTAINER ip link set $WIFI_IFACE type bridge_slave hairpin on 2>/dev/null && { echo 'ok'; break; }
		sleep 3
	done
	if [[ $i -ge 10 ]]; then
		echo -e "\ncouldn't set hairpin mode, wifi clients will probably be unable to talk to each other"
	fi
}

_create_or_start_container() {
	local retry=10
	while [[ $retry -gt 0 ]] ;
	do
		if [[ ! -e /var/run/docker.sock ]] ; then
			echo "docker.sock not found - waiting $retry more seconds for docker daemon to come up..."
			sleep 1
			((retry-=1))
		else
			break
		fi
	done
	if [[ $retry = 0 ]] ; then
		echo "Error: could not connect to docker daemon - exiting."
		exit 1
	fi

	if ! docker inspect $IMAGE:$TAG >/dev/null 2>&1; then
		echo "no image '$IMAGE:$TAG' found, did you forget to run 'make build'?"
		exit 1

	elif docker inspect $CONTAINER >/dev/null 2>&1; then
		echo "* starting container '$CONTAINER'"
		docker start $CONTAINER || exit 1

	else
		_init_network
		echo "* creating container $CONTAINER"
		local lanargs=""
		if [[ "${LAN_DRIVER}" != "direct" ]] ; then
			lanargs="--network $LAN_NAME --ip $LAN_ADDR"
		else
			if [[ ${INT_NAME} ]] ; then 
				if [[ "${INT_NAME}" != "bridge" ]] ; then
					lanargs="--network $INT_NAME --ip $INT_ADDR"
					# else leave lanargs empty
				fi
			else
				lanargs="--network none"
			fi
		fi
		docker create \
		    $lanargs \
			--cap-add NET_ADMIN \
			--cap-add NET_RAW \
			--hostname openwrt \
			--sysctl net.netfilter.nf_conntrack_acct=1 \
			--sysctl net.ipv6.conf.all.disable_ipv6=0 \
			--sysctl net.ipv6.conf.all.forwarding=1 \
			--name $CONTAINER $IMAGE:$TAG >/dev/null || exit 1

		if [[ "${WAN_DRIVER}" != "direct" ]] ; then
			docker network connect $WAN_NAME $CONTAINER
		fi

		_gen_config
		docker start $CONTAINER
	fi
}

_reload_fw() {
	echo "* reloading firewall rules"
	docker exec -i $CONTAINER sh -c '
		for iptables in iptables ip6tables; do
			for table in filter nat mangle; do
				$iptables -t $table -F
			done
		done
		/sbin/fw3 -q restart'
	
	if [[ "${INT_NAME}" = "bridge" ]] ; then
		# docker networks can't do dhcp, so we have to emulate this
		echo * resetting $INT_IFNAME
		sleep 5
		local addr=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $CONTAINER)
		local ippl=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPPrefixLen}}{{end}}' $CONTAINER)
		docker exec -it $CONTAINER ip addr add $addr"/"$ippl dev $INT_IFNAME
		docker exec -it $CONTAINER ip link set $INT_IFNAME up
	fi
}

_prepare_wifi() {
	test $WIFI_ENABLED = 'true' || return
	test -z $WIFI_IFACE && _usage
	_get_phy_from_dev
	_nmcli
	echo "* moving device $WIFI_PHY to docker network namespace"
	sudo iw phy "$WIFI_PHY" set netns $pid
	_set_hairpin $WIFI_IFACE
}

_prepare_network() {
	case $LAN_DRIVER in
		macvlan)
			echo "* setting up host $LAN_DRIVER interface"
			LAN_IFACE=macvlan0
			sudo ip link add $LAN_IFACE link $LAN_PARENT type $LAN_DRIVER mode bridge
			sudo ip link set $LAN_IFACE up
			sudo ip route add $LAN_SUBNET dev $LAN_IFACE
		;;
		ipvlan)
			echo "* setting up host $LAN_DRIVER interface"
			LAN_IFACE=ipvlan0
			sudo ip link add $LAN_IFACE link $LAN_PARENT type $LAN_DRIVER mode l2
			sudo ip link set $LAN_IFACE up
			sudo ip route add $LAN_SUBNET dev $LAN_IFACE
		;;
		bridge)
			LAN_ID=$(docker network inspect $LAN_NAME -f "{{.Id}}")
			LAN_IFACE=br-${LAN_ID:0:12}

			# test if $LAN_PARENT is a VLAN of $WAN_PARENT, create it if it doesn't exist and add it to the bridge
			local lan_array=(${LAN_PARENT//./ })
			if [[ ${lan_array[0]} = $WAN_PARENT ]] && ! ip link show $LAN_PARENT >/dev/null 2>&1 ; then
				sudo ip link add link ${lan_array[0]} name $LAN_PARENT type vlan id ${lan_array[1]}
			fi
			sudo ip link set $LAN_PARENT master $LAN_IFACE
		;;
		direct)
			# move the whole interface to the container, making it unavailable to the host
			sudo ip link set dev $LAN_PARENT netns $CONTAINER
			sudo ip netns exec "$CONTAINER" ip link set "$LAN_PARENT" up
		;;
		*)
			echo "error: invalid LAN network driver type"
			exit 1
		;;
	esac

	case $AUX_DRIVER in
		macvlan)
			echo "Warning: macvlan mode for AUX interface not supported"
			echo "* setting up host $AUX_DRIVER interface"
			AUX_IFACE=macvlan0
			sudo ip link add $AUX_IFACE link $AUX_PARENT type $AUX_DRIVER mode bridge
			sudo ip link set $AUX_IFACE up
			sudo ip route add $AUX_SUBNET dev $AUX_IFACE
		;;
		ipvlan)
			echo "Warning: ipvlan mode for AUX interface not supported"
			echo "* setting up host $AUX_DRIVER interface"
			AUX_IFACE=ipvlan0
			sudo ip link add $AUX_IFACE link $AUX_PARENT type $AUX_DRIVER mode l2
			sudo ip link set $AUX_IFACE up
			sudo ip route add $AUX_SUBNET dev $AUX_IFACE
		;;
		bridge)
			echo "Warning: bridge mode for AUX interface not supported"
			AUX_ID=$(docker network inspect $AUX_NAME -f "{{.Id}}")
			AUX_IFACE=br-${AUX_ID:0:12}

			# test if $AUX_PARENT is a VLAN of $WAN_PARENT, create it if it doesn't exist and add it to the bridge
			local lan_array=(${AUX_PARENT//./ })
			if [[ ${lan_array[0]} = $WAN_PARENT ]] && ! ip link show $AUX_PARENT >/dev/null 2>&1 ; then
				sudo ip link add link ${lan_array[0]} name $AUX_PARENT type vlan id ${lan_array[1]}
			fi
			sudo ip link set $AUX_PARENT master $AUX_IFACE
		;;
		direct)
			# move the whole interface to the container, making it unavailable to the host
			sudo ip link set dev $AUX_PARENT netns $CONTAINER
			sudo ip netns exec "$CONTAINER" ip link set "$AUX_PARENT" up
		;;
		*)
			echo "error: invalid AUX network driver type"
			exit 1
		;;
	esac

	if [[ "${WAN_DRIVER}" = "ipvlan" ]] ; then
		echo "* 'ipvlan' mode selected for WAN interface"
		# need to set DHCP broadcast flag
		# and set clientid to some random value so we get a new lease
		# https://tools.ietf.org/html/rfc1542#section-3.1.1
		local client_id
		client_id=$(tr -dc 'A-F0-9' < /dev/urandom | head -c12)
		docker exec -it $CONTAINER sh -c "
			uci -q set network.wan.broadcast=1
			uci -q set network.wan.clientid=${client_id}
			uci commit"
	elif [[ "${WAN_DRIVER}" = "direct" ]] ; then
			# move the whole interface to the container, making it unavailable to the host
			sudo ip link set dev $WAN_PARENT netns $CONTAINER
			sudo ip netns exec "$CONTAINER" ip link set "$WAN_PARENT" up
	fi

	if [[ "${LAN_DRIVER}" != "direct" ]] ; then
		echo "* getting address via DHCP"
		sudo dhcpcd -q $LAN_IFACE
	fi
}

main() {
	cd "${SCRIPT_DIR}"
	_create_or_start_container

	pid=$(docker inspect -f '{{.State.Pid}}' $CONTAINER)

	echo "* creating netns symlink '$CONTAINER' (pid '$pid')"
	sudo mkdir -p /var/run/netns
	sudo ln -sf /proc/$pid/ns/net /var/run/netns/$CONTAINER

	if [ "$WIFI_ENABLED" = true ] ; then
		_prepare_wifi

	else
		echo "* skipping WiFi setup"

	fi
	_prepare_network

	_reload_fw
	echo "* ready"
}

main
trap "_cleanup" EXIT
tail --pid=$pid -f /dev/null
