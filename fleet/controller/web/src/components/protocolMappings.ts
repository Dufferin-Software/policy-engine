// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

// IANA IP protocol number -> short name mappings for UI display.
//
// The agent/engine already resolves the most common protocols (ANY/ICMP/TCP/
// UDP/ICMPv6) to names; anything else arrives as a bare number string (e.g.
// "2" for IGMP). getProtocolName() resolves those remaining numbers to names
// while passing already-named values through unchanged.

export const protocolNames: { [key: number]: string } = {
  0: 'ANY',
  1: 'ICMP',
  2: 'IGMP',
  4: 'IPIP',
  6: 'TCP',
  8: 'EGP',
  9: 'IGP',
  17: 'UDP',
  41: 'IPv6',
  43: 'IPv6-Route',
  44: 'IPv6-Frag',
  47: 'GRE',
  50: 'ESP',
  51: 'AH',
  58: 'ICMPv6',
  59: 'IPv6-NoNxt',
  60: 'IPv6-Opts',
  88: 'EIGRP',
  89: 'OSPF',
  103: 'PIM',
  112: 'VRRP',
  115: 'L2TP',
  132: 'SCTP',
  136: 'UDPLite',
  137: 'MPLS-in-IP',
}

// Resolve a protocol field to a display name. The value may already be a name
// ('TCP') or a bare number ('2'); numeric values are mapped to their name when
// known, otherwise returned as-is.
export function getProtocolName(protocol: string): string {
  const trimmed = protocol.trim()
  const n = Number(trimmed)
  if (trimmed !== '' && Number.isInteger(n) && String(n) === trimmed) {
    return protocolNames[n] ?? trimmed
  }
  return protocol
}
