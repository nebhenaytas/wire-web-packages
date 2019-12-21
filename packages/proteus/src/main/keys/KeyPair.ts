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
import * as _sodium from 'libsodium-wrappers-sumo';

import * as ClassUtil from '../util/ClassUtil';
import {PublicKey} from './PublicKey';
import {SecretKey} from './SecretKey';

import {InputError} from '../errors/InputError';

/** Construct an ephemeral key pair. */
export class KeyPair {
  publicKey: PublicKey;
  secretKey: SecretKey;

  constructor() {
    this.publicKey = new PublicKey();
    this.secretKey = new SecretKey();
  }

  static async new(): Promise<KeyPair> {
    await _sodium.ready;
    const sodium = _sodium;

    const ed25519KeyPair = sodium.crypto_sign_keypair();

    const keyPairInstance = ClassUtil.newInstance(KeyPair);
    keyPairInstance.secretKey = KeyPair.prototype.constructPrivateKey(ed25519KeyPair);
    keyPairInstance.publicKey = KeyPair.prototype.constructPublicKey(ed25519KeyPair);

    return keyPairInstance;
  }

  /**
   * Ed25519 keys can be converted to Curve25519 keys, so that the same key pair can be
   * used both for authenticated encryption (`crypto_box`) and for signatures (`crypto_sign`).
   * @param ed25519KeyPair Key pair based on Edwards-curve (Ed25519)
   * @returns Constructed private key
   * @see https://download.libsodium.org/doc/advanced/ed25519-curve25519.html
   */
  private constructPrivateKey(ed25519KeyPair: _sodium.KeyPair): SecretKey {
    const secretKeyEd25519 = ed25519KeyPair.privateKey;
    const secretKeyCurve25519 = ed2curve.convertSecretKey(secretKeyEd25519);
    if (secretKeyCurve25519) {
      return SecretKey.new(secretKeyEd25519, secretKeyCurve25519);
    }
    throw new InputError.ConversionError('Could not convert private key with ed2curve.', 409);
  }

  /**
   * @param ed25519KeyPair Key pair based on Edwards-curve (Ed25519)
   * @returns Constructed public key
   */
  private constructPublicKey(ed25519KeyPair: _sodium.KeyPair): PublicKey {
    const publicKeyEd25519 = ed25519KeyPair.publicKey;
    const publicKeyCurve25519 = ed2curve.convertPublicKey(publicKeyEd25519);
    if (publicKeyCurve25519) {
      return PublicKey.new(publicKeyEd25519, publicKeyCurve25519);
    }
    throw new InputError.ConversionError('Could not convert public key with ed2curve.', 408);
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(2);

    encoder.u8(0);
    this.secretKey.encode(encoder);

    encoder.u8(1);
    return this.publicKey.encode(encoder);
  }

  static decode(decoder: CBOR.Decoder): KeyPair {
    const self = ClassUtil.newInstance(KeyPair);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self.secretKey = SecretKey.decode(decoder);
          break;
        case 1:
          self.publicKey = PublicKey.decode(decoder);
          break;
        default:
          decoder.skip();
      }
    }

    return self;
  }
}
