// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 Peter Morrow <pdmorrow@gmail.com>

import { describe, it, expect } from 'vitest'
import { getProtocolName } from './protocolMappings'

describe('getProtocolName', () => {
  it('maps known protocol numbers to names', () => {
    expect(getProtocolName('2')).toBe('IGMP')
    expect(getProtocolName('47')).toBe('GRE')
    expect(getProtocolName('132')).toBe('SCTP')
    expect(getProtocolName('0')).toBe('ANY')
  })

  it('passes already-named values through unchanged', () => {
    expect(getProtocolName('TCP')).toBe('TCP')
    expect(getProtocolName('tcp')).toBe('tcp')
    expect(getProtocolName('ICMPv6')).toBe('ICMPv6')
  })

  it('returns unknown numbers as-is', () => {
    expect(getProtocolName('200')).toBe('200')
    expect(getProtocolName('255')).toBe('255')
  })

  it('handles surrounding whitespace on numeric values', () => {
    expect(getProtocolName(' 6 ')).toBe('TCP')
  })

  it('does not treat non-integer or malformed numerics as protocol numbers', () => {
    expect(getProtocolName('6.5')).toBe('6.5')
    expect(getProtocolName('0x6')).toBe('0x6')
    expect(getProtocolName('')).toBe('')
  })
})
