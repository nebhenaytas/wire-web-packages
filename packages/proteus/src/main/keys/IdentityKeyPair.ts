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
import {IdentityKey} from './IdentityKey';
import {KeyPair} from './KeyPair';
import {SecretKey} from './SecretKey';

export class IdentityKeyPair {
  publicKey: IdentityKey;
  secretKey: SecretKey;
  version: number;

  constructor() {
    this.publicKey = new IdentityKey();
    this.secretKey = new SecretKey();
    this.version = -1;
  }

  static async new(): Promise<IdentityKeyPair> {
    const keyPair = await KeyPair.new();

    const identityKeyPairInstance = ClassUtil.newInstance(IdentityKeyPair);
    identityKeyPairInstance.version = 1;
    identityKeyPairInstance.secretKey = keyPair.secretKey;
    identityKeyPairInstance.publicKey = IdentityKey.new(keyPair.publicKey);

    return identityKeyPairInstance;
  }

  serialise(): ArrayBuffer {
    const encoder = new CBOR.Encoder();
    this.encode(encoder);
    return encoder.get_buffer();
  }

  static deserialise(buffer: ArrayBuffer): IdentityKeyPair {
    const decoder = new CBOR.Decoder(buffer);
    return IdentityKeyPair.decode(decoder);
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(3);
    encoder.u8(0);
    encoder.u8(this.version);
    encoder.u8(1);
    this.secretKey.encode(encoder);
    encoder.u8(2);
    return this.publicKey.encode(encoder);
  }

  static decode(decoder: CBOR.Decoder): IdentityKeyPair {
    const self = ClassUtil.newInstance(IdentityKeyPair);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self.version = decoder.u8();
          break;
        case 1:
          self.secretKey = SecretKey.decode(decoder);
          break;
        case 2:
          self.publicKey = IdentityKey.decode(decoder);
          break;
        default:
          decoder.skip();
      }
    }

    return self;
  }
}
