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

import {CipherKey} from '../derived/CipherKey';
import {MacKey} from '../derived/MacKey';
import * as ClassUtil from '../util/ClassUtil';

export class MessageKeys {
  cipherKey: CipherKey;
  counter: number;
  macKey: MacKey;

  constructor() {
    this.cipherKey = new CipherKey();
    this.counter = -1;
    this.macKey = new MacKey(new Uint8Array([]));
  }

  static new(cipherKey: CipherKey, macKey: MacKey, counter: number): MessageKeys {
    const messageKeysInstance = ClassUtil.newInstance(MessageKeys);
    messageKeysInstance.cipherKey = cipherKey;
    messageKeysInstance.macKey = macKey;
    messageKeysInstance.counter = counter;
    return messageKeysInstance;
  }

  private counterAsNonce(): Uint8Array {
    const nonce = new ArrayBuffer(8);
    new DataView(nonce).setUint32(0, this.counter);
    return new Uint8Array(nonce);
  }

  encrypt(plaintext: string | Uint8Array): Uint8Array {
    return this.cipherKey.encrypt(plaintext, this.counterAsNonce());
  }

  decrypt(ciphertext: Uint8Array): Uint8Array {
    return this.cipherKey.decrypt(ciphertext, this.counterAsNonce());
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(3);
    encoder.u8(0);
    this.cipherKey.encode(encoder);
    encoder.u8(1);
    this.macKey.encode(encoder);
    encoder.u8(2);
    return encoder.u32(this.counter);
  }

  static decode(decoder: CBOR.Decoder): MessageKeys {
    const self = ClassUtil.newInstance(MessageKeys);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self.cipherKey = CipherKey.decode(decoder);
          break;
        case 1:
          self.macKey = MacKey.decode(decoder);
          break;
        case 2:
          self.counter = decoder.u32();
          break;
        default:
          decoder.skip();
      }
    }

    return self;
  }
}
