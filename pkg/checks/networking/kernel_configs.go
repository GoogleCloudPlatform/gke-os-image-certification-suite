// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package networking

import (
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/gke-os-image-certification-suite/pkg/validation"
)

// CiliumKernelFeatures maps Section 2 Kconfig symbol strings (e.g. "CONFIG_BPF_SYSCALL")
// to their corresponding Linux kernel module names and descriptions.
var CiliumKernelFeatures = map[string]KernelFeatureSpec{
	// SECTION 1: Datapath Driver Checklist

	// 1.1 Core Networking & Container Interfaces
	"CONFIG_PACKET": {ModuleName: "af_packet", Description: "Raw packet socket binding"},
	"CONFIG_VETH":   {ModuleName: "veth", Description: "Virtual Ethernet container pairs"},

	// 1.2 Modern nftables Engine & Translation
	"CONFIG_NF_TABLES":  {ModuleName: "nf_tables", Description: "nftables framework"},
	"CONFIG_NFT_COMPAT": {ModuleName: "nft_compat", Description: "Netfilter x_tables over nf_tables compatibility"},
	"CONFIG_NFT_NAT":    {ModuleName: "nft_nat", Description: "nftables NAT support"},

	// 1.3 Core Netfilter & Parent Tables
	"CONFIG_NETFILTER":            {ModuleName: "", Description: "Netfilter framework"},
	"CONFIG_NETFILTER_ADVANCED":   {ModuleName: "", Description: "Advanced Netfilter configuration"},
	"CONFIG_NETFILTER_XTABLES":    {ModuleName: "x_tables", Description: "Core Netfilter Xtables translation layer"},
	"CONFIG_NF_CONNTRACK":         {ModuleName: "nf_conntrack", Description: "Netfilter connection tracking engine"},
	"CONFIG_IP_NF_IPTABLES":       {ModuleName: "ip_tables", Description: "iptables packet filtering"},
	"CONFIG_IP_NF_FILTER":         {ModuleName: "iptable_filter", Description: "iptables filter table"},
	"CONFIG_IP_NF_RAW":            {ModuleName: "iptable_raw", Description: "iptables raw table"},
	"CONFIG_IP_NF_MANGLE":         {ModuleName: "iptable_mangle", Description: "iptables mangle table"},
	"CONFIG_IP_NF_NAT":            {ModuleName: "iptable_nat", Description: "iptables NAT support"},
	"CONFIG_IP_NF_TARGET_REJECT":  {ModuleName: "ipt_REJECT", Description: "iptables REJECT target"},
	"CONFIG_IP_MULTIPLE_TABLES":   {ModuleName: "", Description: "IPv4 policy routing multiple tables"},
	"CONFIG_IPV6":                 {ModuleName: "", Description: "IPv6 protocol support"},
	"CONFIG_IP6_NF_IPTABLES":      {ModuleName: "ip6_tables", Description: "ip6tables packet filtering"},
	"CONFIG_IP6_NF_FILTER":        {ModuleName: "ip6table_filter", Description: "ip6tables filter table"},
	"CONFIG_IP6_NF_RAW":           {ModuleName: "ip6table_raw", Description: "ip6tables raw table"},
	"CONFIG_IP6_NF_MANGLE":        {ModuleName: "ip6table_mangle", Description: "ip6tables mangle table"},
	"CONFIG_IP6_NF_NAT":           {ModuleName: "ip6table_nat", Description: "ip6tables NAT support"},
	"CONFIG_IP6_NF_TARGET_REJECT": {ModuleName: "ip6t_REJECT", Description: "ip6tables REJECT target"},
	"CONFIG_IPV6_MULTIPLE_TABLES": {ModuleName: "", Description: "IPv6 policy routing multiple tables"},

	// 1.4 Xtables Matches & Targets
	"CONFIG_NETFILTER_XT_MATCH_ADDRTYPE":    {ModuleName: "xt_addrtype", Description: "xtables address type match"},
	"CONFIG_NETFILTER_XT_MATCH_CONNTRACK":   {ModuleName: "xt_conntrack", Description: "xtables connection tracking match"},
	"CONFIG_NETFILTER_XT_TARGET_MASQUERADE": {ModuleName: "xt_MASQUERADE", Description: "xtables outbound masquerading"},
	"CONFIG_NETFILTER_XT_TARGET_REDIRECT":   {ModuleName: "xt_REDIRECT", Description: "xtables redirect target"},
	"CONFIG_NETFILTER_XT_NAT":               {ModuleName: "xt_nat", Description: "xtables NAT target"},
	"CONFIG_NETFILTER_NETLINK":              {ModuleName: "nfnetlink", Description: "Netfilter Netlink communication interface"},

	// 1.5 Socket Diagnostics & Lifecycle Management
	"CONFIG_INET_DIAG":     {ModuleName: "inet_diag", Description: "IPv4/IPv6 socket diagnostics"},
	"CONFIG_INET_TCP_DIAG": {ModuleName: "tcp_diag", Description: "TCP socket diagnostics"},
	"CONFIG_INET_UDP_DIAG": {ModuleName: "udp_diag", Description: "UDP socket diagnostics"},

	// SECTION 2: Kernel Configurations for Cilium

	// 2.1 Core Datapath Foundations
	"CONFIG_BPF":             {ModuleName: "", Description: "BPF execution engine"},
	"CONFIG_BPF_EVENTS":      {ModuleName: "", Description: "BPF performance events"},
	"CONFIG_BPF_SYSCALL":     {ModuleName: "", Description: "bpf() system call"},
	"CONFIG_NET_CLS":         {ModuleName: "", Description: "Packet classifier API"},
	"CONFIG_NET_CLS_BPF":     {ModuleName: "cls_bpf", Description: "eBPF packet classifier"},
	"CONFIG_BPF_JIT":         {ModuleName: "", Description: "eBPF JIT compiler"},
	"CONFIG_NET_CLS_ACT":     {ModuleName: "", Description: "Packet action API"},
	"CONFIG_NET_SCH_INGRESS": {ModuleName: "sch_ingress", Description: "Ingress qdisc"},
	"CONFIG_DEBUG_INFO_BTF":  {ModuleName: "", Description: "BTF debug information"},
	"CONFIG_CRYPTO_SHA1":     {ModuleName: "sha1", Description: "SHA1 hash algorithm"},
	"CONFIG_PERF_EVENTS":     {ModuleName: "", Description: "Performance events API"},
	"CONFIG_SCHEDSTATS":      {ModuleName: "", Description: "Scheduler statistics"},

	// 2.2 Cgroups & Socket-Level eBPF Load Balancing
	"CONFIG_CGROUPS":          {ModuleName: "", Description: "Control groups support"},
	"CONFIG_CGROUP_BPF":       {ModuleName: "", Description: "Attach BPF programs to cgroups"},
	"CONFIG_SOCK_CGROUP_DATA": {ModuleName: "", Description: "Socket cgroup association data helper"},

	// 2.3 IP Masquerade
	"CONFIG_NETFILTER_XT_SET":           {ModuleName: "xt_set", Description: "xtables ipset match/target"},
	"CONFIG_IP_SET":                     {ModuleName: "ip_set", Description: "ipset core framework"},
	"CONFIG_IP_SET_HASH_IP":             {ModuleName: "ip_set_hash_ip", Description: "ipset hash:ip map type"},
	"CONFIG_NETFILTER_XT_MATCH_COMMENT": {ModuleName: "xt_comment", Description: "xtables comment match target"},

	// 2.4 Tunneling & Routing
	"CONFIG_VXLAN":     {ModuleName: "vxlan", Description: "VXLAN tunneling support"},
	"CONFIG_GENEVE":    {ModuleName: "geneve", Description: "GENEVE tunneling support"},
	"CONFIG_WIREGUARD": {ModuleName: "wireguard", Description: "Wireguard VPN tunnel support"},
	"CONFIG_FIB_RULES": {ModuleName: "", Description: "Policy routing rules"},
	"CONFIG_XFRM_USER": {ModuleName: "xfrm_user", Description: "IPsec XFRM user configuration interface"},

	// 2.5 L7 and FQDN
	"CONFIG_NETFILTER_XT_TARGET_TPROXY": {ModuleName: "xt_TPROXY", Description: "xtables transparent proxy redirection"},
	"CONFIG_NETFILTER_XT_TARGET_MARK":   {ModuleName: "xt_mark", Description: "xtables mark packet target"},
	"CONFIG_NETFILTER_XT_TARGET_CT":     {ModuleName: "xt_CT", Description: "xtables raw CT connection tracking template target"},
	"CONFIG_NETFILTER_XT_MATCH_MARK":    {ModuleName: "xt_mark", Description: "xtables mark packet match"},
	"CONFIG_NETFILTER_XT_MATCH_SOCKET":  {ModuleName: "xt_socket", Description: "xtables socket match"},

	// 2.6 Bandwidth Manager
	"CONFIG_NET_SCH_FQ": {ModuleName: "sch_fq", Description: "Fair Queue packet scheduler"},
}

type ciliumKernelCheck struct {
	configSymbol string
}

func (c *ciliumKernelCheck) Name() string {
	return "networking/cilium-" + c.configSymbol
}

func (c *ciliumKernelCheck) Description() string {
	if spec, ok := CiliumKernelFeatures[c.configSymbol]; ok && spec.Description != "" {
		return fmt.Sprintf("Verifies Cilium requirement %s (%s)", c.configSymbol, spec.Description)
	}
	return fmt.Sprintf("Verifies Cilium requirement %s", c.configSymbol)
}

func (c *ciliumKernelCheck) Tier() validation.Tier { return validation.Tier1 }
func (c *ciliumKernelCheck) Destructive() bool     { return false }

func (c *ciliumKernelCheck) Run(ctx context.Context, runner validation.SSHRunner) error {
	spec, ok := CiliumKernelFeatures[c.configSymbol]
	if !ok {
		// Fallback for unknown symbols not yet in the dictionary
		spec = KernelFeatureSpec{ModuleName: ""}
	}
	return VerifyKernelFeature(ctx, runner, c.configSymbol, spec.ModuleName)
}

func init() {
	for symbol := range CiliumKernelFeatures {
		validation.Register(&ciliumKernelCheck{
			configSymbol: symbol,
		})
	}
}
