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

describe('Public Key', () => {
  it('rejects shared secrets at the point of infinity', async () => {
    try {
      const emptyCurve = new Uint8Array([1].concat(Array.from({length: 30})));
      const aliceKeypair = await Proteus.keys.KeyPair.new();
      const bobKeypair = await Proteus.keys.KeyPair.new();

      const aliceSecretKey = aliceKeypair.secretKey.sharedSecret(bobKeypair.publicKey);
      const bobSecretKey = bobKeypair.secretKey.sharedSecret(aliceKeypair.publicKey);

      expect(aliceSecretKey).toEqual(bobSecretKey);

      bobKeypair.publicKey.pubCurve = emptyCurve;

      aliceKeypair.secretKey.sharedSecret(bobKeypair.publicKey);

      fail();
    } catch (error) {
      expect(error instanceof TypeError).toBe(true);
    }
  });
});
