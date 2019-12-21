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
import * as sodium from 'libsodium-wrappers-sumo';

beforeAll(async () => {
  await sodium.ready;
});

describe('PreKey', () => {
  describe('Generation', () => {
    it('generates a PreKey', async () => {
      const keyId = 0;
      const pk = await Proteus.keys.PreKey.new(keyId);
      expect(pk.keyId).toBe(keyId);
    });

    it('generates a PreKey of last resort', async () => {
      const pk = await Proteus.keys.PreKey.lastResort();
      expect(pk.keyId).toBe(Proteus.keys.PreKey.MAX_PREKEY_ID);
    });

    it('rejects undefined IDs', async () => {
      try {
        await (Proteus as any).keys.PreKey.new(undefined);
        fail();
      } catch (error) {
        expect(error instanceof Proteus.errors.InputError.TypeError).toBe(true);
        expect(error.code).toBe(Proteus.errors.InputError.CODE.CASE_404);
      }
    });

    it('rejects string IDs', async () => {
      try {
        await (Proteus as any).keys.PreKey.new('foo');
        fail();
      } catch (error) {
        expect(error instanceof Proteus.errors.InputError.TypeError).toBe(true);
        expect(error.code).toBe(Proteus.errors.InputError.CODE.CASE_403);
      }
    });

    it('rejects too low IDs', async () => {
      try {
        await Proteus.keys.PreKey.new(-1);
        fail();
      } catch (error) {
        expect(error instanceof Proteus.errors.InputError.RangeError).toBe(true);
        expect(error.code).toBe(Proteus.errors.InputError.CODE.CASE_400);
      }
    });

    it('rejects too high IDs', async () => {
      try {
        await Proteus.keys.PreKey.new(65537);
        fail();
      } catch (error) {
        expect(error instanceof Proteus.errors.InputError.RangeError).toBe(true);
        expect(error.code).toBe(Proteus.errors.InputError.CODE.CASE_400);
      }
    });

    it('rejects floating point IDs', async () => {
      try {
        await Proteus.keys.PreKey.new(4242.42);
        fail();
      } catch (error) {
        expect(error instanceof Proteus.errors.InputError.TypeError).toBe(true);
        expect(error.code).toBe(Proteus.errors.InputError.CODE.CASE_403);
      }
    });

    it('throws errors with error codes', async () => {
      try {
        await Proteus.keys.PreKey.new(Proteus.keys.PreKey.MAX_PREKEY_ID + 1);
        fail();
      } catch (error) {
        expect(error instanceof Proteus.errors.InputError.RangeError).toBe(true);
        expect(error.code).toBe(Proteus.errors.InputError.CODE.CASE_400);
      }
    });

    it('generates ranges of PreKeys', async () => {
      let prekeys = await Proteus.keys.PreKey.generatePrekeys(0, 0);
      expect(prekeys.length).toBe(0);

      prekeys = await Proteus.keys.PreKey.generatePrekeys(0, 1);
      expect(prekeys.length).toBe(1);
      expect(prekeys[0].keyId).toBe(0);

      prekeys = await Proteus.keys.PreKey.generatePrekeys(0, 10);
      expect(prekeys.length).toBe(10);
      expect(prekeys[0].keyId).toBe(0);
      expect(prekeys[9].keyId).toBe(9);

      prekeys = await Proteus.keys.PreKey.generatePrekeys(3000, 10);
      expect(prekeys.length).toBe(10);
      expect(prekeys[0].keyId).toBe(3000);
      expect(prekeys[9].keyId).toBe(3009);
    });

    it('does not include the last resort pre key', async () => {
      let prekeys = await Proteus.keys.PreKey.generatePrekeys(65530, 10);
      expect(prekeys.length).toBe(10);
      expect(prekeys[0].keyId).toBe(65530);
      expect(prekeys[1].keyId).toBe(65531);
      expect(prekeys[2].keyId).toBe(65532);
      expect(prekeys[3].keyId).toBe(65533);
      expect(prekeys[4].keyId).toBe(65534);
      expect(prekeys[5].keyId).toBe(0);
      expect(prekeys[6].keyId).toBe(1);
      expect(prekeys[7].keyId).toBe(2);
      expect(prekeys[8].keyId).toBe(3);
      expect(prekeys[9].keyId).toBe(4);

      prekeys = await Proteus.keys.PreKey.generatePrekeys(Proteus.keys.PreKey.MAX_PREKEY_ID, 1);
      expect(prekeys.length).toBe(1);
      expect(prekeys[0].keyId).toBe(0);
    });
  });

  describe('Serialisation', () => {
    it('serialises and deserialises correctly', async () => {
      const pk = await Proteus.keys.PreKey.new(0);
      const pkBytes = pk.serialise();
      const pkCopy = Proteus.keys.PreKey.deserialise(pkBytes);

      expect(pkCopy.version).toBe(pk.version);
      expect(pkCopy.keyId).toBe(pk.keyId);
      expect(pkCopy.keyPair.publicKey.fingerprint()).toBe(pk.keyPair.publicKey.fingerprint());
      expect(sodium.to_hex(new Uint8Array(pkBytes))).toBe(sodium.to_hex(new Uint8Array(pkCopy.serialise())));
    });
  });
});
