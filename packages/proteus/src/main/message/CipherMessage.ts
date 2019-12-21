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

import {InputError} from '../errors/InputError';
import {PublicKey} from '../keys/PublicKey';
import * as ClassUtil from '../util/ClassUtil';
import {Message} from './Message';
import {SessionTag} from './SessionTag';

export class CipherMessage extends Message {
  cipherText: Uint8Array;
  counter: number;
  prevCounter: number;
  ratchetKey: PublicKey;
  sessionTag: SessionTag;

  constructor() {
    super();
    this.cipherText = new Uint8Array([]);
    this.counter = -1;
    this.prevCounter = -1;
    this.ratchetKey = new PublicKey();
    this.sessionTag = new SessionTag();
  }

  static new(
    sessionTag: SessionTag,
    counter: number,
    prevCounter: number,
    ratchetKey: PublicKey,
    cipherText: Uint8Array,
  ): CipherMessage {
    const cipherMessageInstance = ClassUtil.newInstance(CipherMessage);

    cipherMessageInstance.sessionTag = sessionTag;
    cipherMessageInstance.counter = counter;
    cipherMessageInstance.prevCounter = prevCounter;
    cipherMessageInstance.ratchetKey = ratchetKey;
    cipherMessageInstance.cipherText = cipherText;

    Object.freeze(cipherMessageInstance);
    return cipherMessageInstance;
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(5);
    encoder.u8(0);
    this.sessionTag.encode(encoder);
    encoder.u8(1);
    encoder.u32(this.counter);
    encoder.u8(2);
    encoder.u32(this.prevCounter);
    encoder.u8(3);
    this.ratchetKey.encode(encoder);
    encoder.u8(4);
    return encoder.bytes(this.cipherText);
  }

  static decode(decoder: CBOR.Decoder): CipherMessage {
    let sessionTag = null;
    let counter = null;
    let prevCounter = null;
    let ratchetKey = null;
    let cipherText = null;

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          sessionTag = SessionTag.decode(decoder);
          break;
        case 1:
          counter = decoder.u32();
          break;
        case 2:
          prevCounter = decoder.u32();
          break;
        case 3:
          ratchetKey = PublicKey.decode(decoder);
          break;
        case 4:
          cipherText = new Uint8Array(decoder.bytes());
          break;
        default:
          decoder.skip();
      }
    }

    counter = Number(counter);
    prevCounter = Number(prevCounter);

    if (sessionTag && !isNaN(counter) && !isNaN(prevCounter) && ratchetKey && cipherText) {
      return CipherMessage.new(sessionTag, counter, prevCounter, ratchetKey, cipherText);
    } else {
      throw new InputError.TypeError(`Given CipherMessage doesn't match expected signature.`, InputError.CODE.CASE_405);
    }
  }
}
