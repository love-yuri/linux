#!/bin/bash
# SPDX-License-Identifier: GPL-2.0

# +---------------------------------------------+      +----------------------+
# | H1 (vrf)                                    |      |             H2 (vrf) |
# |    + $h1.100            + $h1.200           |      |  + $h2               |
# |    | 192.0.2.1/28       | 192.0.2.17/28     |      |  | 192.0.2.130/28    |
# |    | 2001:db8:1::1/64   | 2001:db8:3::1/64  |      |  | 192.0.2.146/28    |
# |    \_________ __________/                   |      |  | 2001:db8:2::2/64  |
# |              V                              |      |  | 2001:db8:4::2/64  |
# |              + $h1                          |      |  |                   |
# +--------------|------------------------------+      +--|-------------------+
#                |                                        |
# +--------------|----------------------------------------|-------------------+
# | SW           + $swp1                                  + $swp2             |
# |              |                                          192.0.2.129/28    |
# |              |                                          192.0.2.145/28    |
# |              |                                          2001:db8:2::1/64  |
# |      ________^___________________________               2001:db8:4::1/64  |
# |     /                                    \                                |
# | +---|------------------------------+ +---|------------------------------+ |
# | |   + $swp1.100   BR1 (802.1d)     | |   + $swp1.200   BR2 (802.1d)     | |
# | |                 192.0.2.2/28     | |                 192.0.2.18/28    | |
# | |                 2001:db8:1::2/64 | |                 2001:db8:3::2/64 | |
# | |                                  | |                                  | |
# | +----------------------------------+ +----------------------------------+ |
# +---------------------------------------------------------------------------+

ALL_TESTS="
	ping_ipv4
	ping_ipv6
	config_remaster
	ping_ipv4
	ping_ipv6
"
NUM_NETIFS=4
source lib.sh

h1_create()
{
	simple_if_init $h1
	vlan_create $h1 100 v$h1 192.0.2.1/28 2001:db8:1::1/64
	vlan_create $h1 200 v$h1 192.0.2.17/28 2001:db8:3::1/64
	ip -4 route add 192.0.2.128/28 vrf v$h1 nexthop via 192.0.2.2
	ip -4 route add 192.0.2.144/28 vrf v$h1 nexthop via 192.0.2.18
	ip -6 route add 2001:db8:2::/64 vrf v$h1 nexthop via 2001:db8:1::2
	ip -6 route add 2001:db8:4::/64 vrf v$h1 nexthop via 2001:db8:3::2
}

h1_destroy()
{
	ip -6 route del 2001:db8:4::/64 vrf v$h1
	ip -6 route del 2001:db8:2::/64 vrf v$h1
	ip -4 route del 192.0.2.144/28 vrf v$h1
	ip -4 route del 192.0.2.128/28 vrf v$h1
	vlan_destroy $h1 200
	vlan_destroy $h1 100
	simple_if_fini $h1
}

h2_create()
{
	simple_if_init $h2 192.0.2.130/28 2001:db8:2::2/64 \
			   192.0.2.146/28 2001:db8:4::2/64
	ip -4 route add 192.0.2.0/28 vrf v$h2 nexthop via 192.0.2.129
	ip -4 route add 192.0.2.16/28 vrf v$h2 nexthop via 192.0.2.145
	ip -6 route add 2001:db8:1::/64 vrf v$h2 nexthop via 2001:db8:2::1
	ip -6 route add 2001:db8:3::/64 vrf v$h2 nexthop via 2001:db8:4::1
}

h2_destroy()
{
	ip -6 route del 2001:db8:3::/64 vrf v$h2
	ip -6 route del 2001:db8:1::/64 vrf v$h2
	ip -4 route del 192.0.2.16/28 vrf v$h2
	ip -4 route del 192.0.2.0/28 vrf v$h2
	simple_if_fini $h2 192.0.2.130/28 2001:db8:2::2/64 \
			   192.0.2.146/28 2001:db8:4::2/64
}

router_create()
{
	ip link set dev $swp1 up

	vlan_create $swp1 100
	ip link add name br1 type bridge vlan_filtering 0
	ip link set dev br1 address $(mac_get $swp1.100)
	ip link set dev $swp1.100 master br1
	__addr_add_del br1 add 192.0.2.2/28 2001:db8:1::2/64
	ip link set dev br1 up

	vlan_create $swp1 200
	ip link add name br2 type bridge vlan_filtering 0
	ip link set dev br2 address $(mac_get $swp1.200)
	ip link set dev $swp1.200 master br2
	__addr_add_del br2 add 192.0.2.18/28 2001:db8:3::2/64
	ip link set dev br2 up

	ip link set dev $swp2 up
	__addr_add_del $swp2 add 192.0.2.129/28 2001:db8:2::1/64 \
				 192.0.2.145/28 2001:db8:4::1/64
}

router_destroy()
{
	__addr_add_del $swp2 del 192.0.2.129/28 2001:db8:2::1/64 \
				 192.0.2.145/28 2001:db8:4::1/64
	ip link set dev $swp2 down

	__addr_add_del br2 del 192.0.2.18/28 2001:db8:3::2/64
	ip link set dev $swp1.200 nomaster
	ip link del dev br2
	vlan_destroy $swp1 200

	__addr_add_del br1 del 192.0.2.2/28 2001:db8:1::2/64
	ip link set dev $swp1.100 nomaster
	ip link del dev br1
	vlan_destroy $swp1 100

	ip link set dev $swp1 down
}

config_remaster()
{
	log_info "Remaster bridge slaves"

	ip link set dev $swp1.100 nomaster
	ip link set dev $swp1.200 nomaster
	sleep 2
	ip link set dev $swp1.200 master br2
	ip link set dev $swp1.100 master br1
}

setup_prepare()
{
	h1=${NETIFS[p1]}
	swp1=${NETIFS[p2]}

	swp2=${NETIFS[p3]}
	h2=${NETIFS[p4]}

	vrf_prepare

	h1_create
	h2_create

	router_create

	forwarding_enable
}

cleanup()
{
	pre_cleanup

	forwarding_restore

	router_destroy

	h2_destroy
	h1_destroy

	vrf_cleanup
}

ping_ipv4()
{
	ping_test $h1 192.0.2.130 ": via 100"
	ping_test $h1 192.0.2.146 ": via 200"
}

ping_ipv6()
{
	ping6_test $h1 2001:db8:2::2 ": via 100"
	ping6_test $h1 2001:db8:4::2 ": via 200"
}

trap cleanup EXIT

setup_prepare
setup_wait

tests_run

exit $EXIT_STATUS
