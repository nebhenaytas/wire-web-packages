/*
 * Wire
 * Copyright (C) 2018 Wire Swiss GmbH
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see http://www.gnu.org/licenses/.
 *
 */

import * as CBOR from '@wireapp/cbor';
import * as Proteus from '@wireapp/proteus';

describe('Envelope', () => {
  const macKey = new Proteus.derived.MacKey(new Uint8Array(32).fill(1));

  const sessionTag = Proteus.message.SessionTag.new();

  let identityKey: Proteus.keys.IdentityKey;
  let baseKey: Proteus.keys.PublicKey;
  let ratchetKey: Proteus.keys.PublicKey;

  beforeAll(async () => {
    identityKey = Proteus.keys.IdentityKey.new((await Proteus.keys.KeyPair.new()).publicKey);
    baseKey = (await Proteus.keys.KeyPair.new()).publicKey;
    ratchetKey = (await Proteus.keys.KeyPair.new()).publicKey;
  });

  it('encapsulates a CipherMessage', () => {
    const msg = Proteus.message.CipherMessage.new(sessionTag, 42, 3, ratchetKey, new Uint8Array([1, 2, 3, 4, 5]));
    const env = Proteus.message.Envelope.new(macKey, msg);

    expect(env.verify(macKey)).toBe(true);
  });

  it('encapsulates a PreKeyMessage', () => {
    const msg = Proteus.message.PreKeyMessage.new(
      42,
      baseKey,
      identityKey,
      Proteus.message.CipherMessage.new(sessionTag, 42, 43, ratchetKey, new Uint8Array([1, 2, 3, 4])),
    );

    const env = Proteus.message.Envelope.new(macKey, msg);
    expect(env.verify(macKey)).toBe(true);
  });

  it('encodes to and decode from CBOR', () => {
    const msg = Proteus.message.PreKeyMessage.new(
      42,
      baseKey,
      identityKey,
      Proteus.message.CipherMessage.new(sessionTag, 42, 43, ratchetKey, new Uint8Array([1, 2, 3, 4])),
    );

    const env = Proteus.message.Envelope.new(macKey, msg);
    expect(env.verify(macKey)).toBe(true);

    const envBytes = env.serialise();
    const envCpy = Proteus.message.Envelope.deserialise(envBytes);

    expect(envCpy.verify(macKey)).toBe(true);
  });

  it('fails when passing invalid input', () => {
    const emptyBuffer = new ArrayBuffer(0);
    try {
      Proteus.message.Envelope.deserialise(emptyBuffer);
    } catch (error) {
      expect(error instanceof CBOR.DecodeError).toBe(true);
    }
  });
});
