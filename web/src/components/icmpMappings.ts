// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

// ICMP type/code mappings for IPv4 and IPv6

export const icmp4Types: { [key: string]: string } = {
  "0": "Echo Reply",
  "3": "Destination Unreachable",
  "4": "Source Quench (Deprecated)",
  "5": "Redirect",
  "6": "Alternate Host Address (Deprecated)",
  "8": "Echo Request",
  "9": "Router Advertisement",
  "10": "Router Solicitation",
  "11": "Time Exceeded",
  "12": "Parameter Problem",
  "13": "Timestamp Request",
  "14": "Timestamp Reply",
  "15": "Information Request (Deprecated)",
  "16": "Information Reply (Deprecated)",
  "17": "Address Mask Request (Deprecated)",
  "18": "Address Mask Reply (Deprecated)",
  "30": "Traceroute (Deprecated)",
  "31": "Datagram Conversion Error (Deprecated)",
  "32": "Mobile Host Redirect",
  "33": "IPv6 Where-Are-You",
  "34": "IPv6 I-Am-Here",
  "35": "Mobile Registration Request",
  "36": "Mobile Registration Reply",
  "37": "Domain Name Request",
  "38": "Domain Name Reply",
  "39": "SKIP",
  "40": "Photuris (Security Failures)"
};

export const icmp4Codes: { [type: string]: { [code: string]: string } } = {
  "3": {
    "0": "Network Unreachable",
    "1": "Host Unreachable",
    "2": "Protocol Unreachable",
    "3": "Port Unreachable",
    "4": "Fragmentation Needed and DF Set",
    "5": "Source Route Failed",
    "6": "Destination Network Unknown",
    "7": "Destination Host Unknown",
    "8": "Source Host Isolated",
    "9": "Network Administratively Prohibited",
    "10": "Host Administratively Prohibited",
    "11": "Network Unreachable for ToS",
    "12": "Host Unreachable for ToS",
    "13": "Communication Administratively Prohibited",
    "14": "Host Precedence Violation",
    "15": "Precedence Cutoff in Effect"
  },
  "5": {
    "0": "Redirect Datagram for the Network",
    "1": "Redirect Datagram for the Host",
    "2": "Redirect for ToS and Network",
    "3": "Redirect for ToS and Host"
  },
  "11": {
    "0": "TTL Expired in Transit",
    "1": "Fragment Reassembly Time Exceeded"
  },
  "12": {
    "0": "Pointer Indicates the Error",
    "1": "Missing Required Option",
    "2": "Bad Length"
  },
  "40": {
    "0": "Bad SPI",
    "1": "Authentication Failed",
    "2": "Decompression Failed",
    "3": "Decryption Failed",
    "4": "Need Authentication",
    "5": "Need Authorization"
  }
};

export const icmp6Types: { [key: string]: string } = {
  "1": "Destination Unreachable",
  "2": "Packet Too Big",
  "3": "Time Exceeded",
  "4": "Parameter Problem",
  "128": "Echo Request",
  "129": "Echo Reply",
  "130": "Multicast Listener Query (MLD)",
  "131": "Multicast Listener Report (MLD)",
  "132": "Multicast Listener Done (MLD)",
  "143": "Multicast Listener Report v2",
  "133": "Router Solicitation (NDP)",
  "134": "Router Advertisement (NDP)",
  "135": "Neighbor Solicitation (NDP)",
  "136": "Neighbor Advertisement (NDP)",
  "137": "Redirect (NDP)",
  "138": "Router Renumbering",
  "139": "ICMP Node Information Query",
  "140": "ICMP Node Information Response",
  "141": "Inverse Neighbor Discovery Solicitation",
  "142": "Inverse Neighbor Discovery Advertisement",
  "148": "Certification Path Solicitation",
  "149": "Certification Path Advertisement",
  "151": "Multicast Router Advertisement",
  "152": "Multicast Router Solicitation",
  "153": "Multicast Router Termination",
  "155": "RPL Control Message",
  "160": "Extended Echo Request",
  "161": "Extended Echo Reply"
};

export const icmp6Codes: { [type: string]: { [code: string]: string } } = {
  "1": {
    "0": "No Route to Destination",
    "1": "Communication with Destination Administratively Prohibited",
    "2": "Beyond Scope of Source Address",
    "3": "Address Unreachable",
    "4": "Port Unreachable",
    "5": "Source Address Failed Ingress/Egress Policy",
    "6": "Reject Route to Destination",
    "7": "Error in Source Routing Header"
  },
  "2": {
    "0": "Packet Too Big"
  },
  "3": {
    "0": "Hop Limit Exceeded in Transit",
    "1": "Fragment Reassembly Time Exceeded"
  },
  "4": {
    "0": "Erroneous Header Field Encountered",
    "1": "Unrecognized Next Header Type",
    "2": "Unrecognized IPv6 Option"
  }
};

export function getIcmpTypeName(type: number | string, isIpv6: boolean = false): string {
  const t = String(type);
  return isIpv6 ? icmp6Types[t] || t : icmp4Types[t] || t;
}

export function getIcmpCodeName(type: number | string, code: number | string, isIpv6: boolean = false): string {
  const t = String(type);
  const c = String(code);
  const table = isIpv6 ? icmp6Codes : icmp4Codes;
  if (table[t] && table[t][c]) {
    return table[t][c];
  }
  return c;
}
