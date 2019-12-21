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

import * as Proteus from '@wireapp/proteus';

describe('KeyPair', () => {
  it('signs a message and verifies the signature', async () => {
    const kp = await Proteus.keys.KeyPair.new();
    const msg = 'what do ya want for nothing?';
    const sig = kp.secretKey.sign(msg);
    const badSignature = new Uint8Array(sig);

    badSignature.forEach((obj, index) => {
      badSignature[index] = ~badSignature[index];
    });

    expect(kp.publicKey.verify(sig, msg)).toBe(true);
    expect(kp.publicKey.verify(badSignature, msg)).toBe(false);
  });

  it('computes a Diffie-Hellman shared secret', async () => {
    const [keypairA, keypairB] = await Promise.all([Proteus.keys.KeyPair.new(), Proteus.keys.KeyPair.new()]);
    const sharedA = keypairA.secretKey.sharedSecret(keypairB.publicKey);
    const sharedB = keypairB.secretKey.sharedSecret(keypairA.publicKey);
    expect(sharedA).toEqual(sharedB);
  });
});
