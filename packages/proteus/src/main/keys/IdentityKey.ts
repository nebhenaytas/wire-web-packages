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

import * as ClassUtil from '../util/ClassUtil';
import {PublicKey} from './PublicKey';

/**
 * Construct a long-term identity key pair.
 *
 * Every client has a long-term identity key pair.
 * Long-term identity keys are used to initialise "sessions" with other clients (triple DH).
 */
export class IdentityKey {
  publicKey: PublicKey;

  constructor() {
    this.publicKey = new PublicKey();
  }

  static new(publicKey: PublicKey): IdentityKey {
    const identityKeyInstance = ClassUtil.newInstance(IdentityKey);
    identityKeyInstance.publicKey = publicKey;
    return identityKeyInstance;
  }

  fingerprint(): string {
    return this.publicKey.fingerprint();
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(1);
    encoder.u8(0);
    return this.publicKey.encode(encoder);
  }

  static decode(decoder: CBOR.Decoder): IdentityKey {
    let self = ClassUtil.newInstance(PublicKey);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self = PublicKey.decode(decoder);
          break;
        default:
          decoder.skip();
      }
    }

    return IdentityKey.new(self);
  }
}
