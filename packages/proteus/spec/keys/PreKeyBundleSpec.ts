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

describe('PreKeyBundle', () => {
  it('creates a bundle', async () => {
    const [idPair, prekey] = await Promise.all([Proteus.keys.IdentityKeyPair.new(), Proteus.keys.PreKey.new(1)]);
    const bundle = Proteus.keys.PreKeyBundle.new(idPair.publicKey, prekey);
    expect(bundle.verify()).toBe(Proteus.keys.PreKeyAuth.UNKNOWN);
  });

  it('creates a valid signed bundle', async () => {
    const [idPair, prekey] = await Promise.all([Proteus.keys.IdentityKeyPair.new(), Proteus.keys.PreKey.new(1)]);
    const bundle = Proteus.keys.PreKeyBundle.signed(idPair, prekey);
    expect(bundle.verify()).toBe(Proteus.keys.PreKeyAuth.VALID);
  });

  it('serialises and deserialise an unsigned bundle', async () => {
    const [idPair, prekey] = await Promise.all([Proteus.keys.IdentityKeyPair.new(), Proteus.keys.PreKey.new(1)]);
    const bundle = Proteus.keys.PreKeyBundle.new(idPair.publicKey, prekey);

    expect(bundle.verify()).toBe(Proteus.keys.PreKeyAuth.UNKNOWN);

    const pkbBytes = bundle.serialise();
    const pkbCopy = Proteus.keys.PreKeyBundle.deserialise(pkbBytes);

    expect(pkbCopy.verify()).toBe(Proteus.keys.PreKeyAuth.UNKNOWN);
    expect(pkbCopy.version).toBe(bundle.version);
    expect(pkbCopy.prekeyId).toBe(bundle.prekeyId);
    expect(pkbCopy.publicKey.fingerprint()).toBe(bundle.publicKey.fingerprint());
    expect(pkbCopy.identityKey.fingerprint()).toBe(bundle.identityKey.fingerprint());
    expect(pkbCopy.signature).toEqual(bundle.signature);
    expect(sodium.to_hex(new Uint8Array(pkbBytes))).toBe(sodium.to_hex(new Uint8Array(pkbCopy.serialise())));
  });

  it('should serialise and deserialise a signed bundle', async () => {
    const [idPair, prekey] = await Promise.all([Proteus.keys.IdentityKeyPair.new(), Proteus.keys.PreKey.new(1)]);
    const bundle = Proteus.keys.PreKeyBundle.signed(idPair, prekey);
    expect(bundle.verify()).toBe(Proteus.keys.PreKeyAuth.VALID);

    const pkbBytes = bundle.serialise();
    const pkbCopy = Proteus.keys.PreKeyBundle.deserialise(pkbBytes);

    expect(pkbCopy.verify()).toBe(Proteus.keys.PreKeyAuth.VALID);

    expect(pkbCopy.version).toBe(bundle.version);
    expect(pkbCopy.prekeyId).toBe(bundle.prekeyId);
    expect(pkbCopy.publicKey.fingerprint()).toBe(bundle.publicKey.fingerprint());
    expect(pkbCopy.identityKey.fingerprint()).toBe(bundle.identityKey.fingerprint());
    expect(sodium.to_hex(pkbCopy.signature!)).toBe(sodium.to_hex(bundle.signature!));
    expect(sodium.to_hex(new Uint8Array(pkbBytes))).toBe(sodium.to_hex(new Uint8Array(pkbCopy.serialise())));
  });

  it('should generate a serialised JSON format', async () => {
    const preKeyId = 72;

    const [identityKeyPair, preKey] = await Promise.all([
      Proteus.keys.IdentityKeyPair.new(),
      Proteus.keys.PreKey.new(preKeyId),
    ]);
    const publicIdentityKey = identityKeyPair.publicKey;
    const preKeyBundle = Proteus.keys.PreKeyBundle.new(publicIdentityKey, preKey);
    const serialisedPreKeyBundleJson = preKeyBundle.serialisedJson();

    expect(serialisedPreKeyBundleJson.id).toBe(preKeyId);

    const serialisedArrayBufferView = sodium.from_base64(
      serialisedPreKeyBundleJson.key,
      sodium.base64_variants.ORIGINAL,
    );
    const serialisedArrayBuffer = serialisedArrayBufferView.buffer;
    const deserialisedPreKeyBundle = Proteus.keys.PreKeyBundle.deserialise(serialisedArrayBuffer);

    expect(deserialisedPreKeyBundle.publicKey).toEqual(preKeyBundle.publicKey);
  });
});
