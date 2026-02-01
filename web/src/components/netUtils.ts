// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Dufferin Software <support@dufferinsw.com>

// Utility to check if an IP address is multicast (IPv4 or IPv6)

export function isMulticast(addr: string): boolean {
  // IPv4 multicast: 224.0.0.0/4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(addr)) {
    const octets = addr.split('.').map(Number)
    return octets[0] >= 224 && octets[0] <= 239
  }
  // IPv6 multicast: ff00::/8
  if (addr.includes(':')) {
    return addr.trim().toLowerCase().startsWith('ff')
  }
  return false
}
