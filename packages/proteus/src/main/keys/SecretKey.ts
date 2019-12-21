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
import * as ed2curve from 'ed2curve';
import * as sodium from 'libsodium-wrappers-sumo';

import * as ClassUtil from '../util/ClassUtil';

import {InputError} from '../errors/InputError';
import * as ArrayUtil from '../util/ArrayUtil';
import {PublicKey} from './PublicKey';

export class SecretKey {
  secCurve: Uint8Array;
  secEdward: Uint8Array;

  constructor() {
    this.secCurve = new Uint8Array([]);
    this.secEdward = new Uint8Array([]);
  }

  static new(secEdward: Uint8Array, secCurve: Uint8Array): SecretKey {
    const secretKeyInstance = ClassUtil.newInstance(SecretKey);

    secretKeyInstance.secEdward = secEdward;
    secretKeyInstance.secCurve = secCurve;
    return secretKeyInstance;
  }

  /**
   * This function can be used to compute a message signature.
   * @param message Message to be signed
   * @returns A message signature
   */
  sign(message: Uint8Array | string): Uint8Array {
    return sodium.crypto_sign_detached(message, this.secEdward);
  }

  /**
   * This function can be used to compute a shared secret given a user's secret key and another
   * user's public key.
   * @param publicKey Another user's public key
   * @returns Array buffer view of the computed shared secret
   */
  sharedSecret(publicKey: PublicKey): Uint8Array {
    const sharedSecret = sodium.crypto_scalarmult(this.secCurve, publicKey.pubCurve);

    ArrayUtil.assertIsNotZeros(sharedSecret);

    return sharedSecret;
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(1);
    encoder.u8(0);
    return encoder.bytes(this.secEdward);
  }

  static decode(decoder: CBOR.Decoder): SecretKey {
    const self = ClassUtil.newInstance(SecretKey);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self.secEdward = new Uint8Array(decoder.bytes());
          break;
        default:
          decoder.skip();
      }
    }

    const secCurve = ed2curve.convertSecretKey(self.secEdward);
    if (secCurve) {
      self.secCurve = secCurve;
      return self;
    }
    throw new InputError.ConversionError('Could not convert public key with ed2curve.', 408);
  }
}
