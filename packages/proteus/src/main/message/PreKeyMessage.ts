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

import {IdentityKey} from '../keys/IdentityKey';
import {PublicKey} from '../keys/PublicKey';
import * as ClassUtil from '../util/ClassUtil';

import {InputError} from '../errors/InputError';
import {CipherMessage} from './CipherMessage';
import {Message} from './Message';

export class PreKeyMessage extends Message {
  baseKey: PublicKey;
  identityKey: IdentityKey;
  message: CipherMessage;
  prekeyId: number;

  constructor() {
    super();
    this.baseKey = new PublicKey();
    this.identityKey = new IdentityKey();
    this.message = new CipherMessage();
    this.prekeyId = -1;
  }

  static new(prekeyId: number, baseKey: PublicKey, identityKey: IdentityKey, message: CipherMessage): PreKeyMessage {
    const preyKeyMessageInstance = ClassUtil.newInstance(PreKeyMessage);

    preyKeyMessageInstance.prekeyId = prekeyId;
    preyKeyMessageInstance.baseKey = baseKey;
    preyKeyMessageInstance.identityKey = identityKey;
    preyKeyMessageInstance.message = message;

    Object.freeze(preyKeyMessageInstance);
    return preyKeyMessageInstance;
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(4);
    encoder.u8(0);
    encoder.u16(this.prekeyId);
    encoder.u8(1);
    this.baseKey.encode(encoder);
    encoder.u8(2);
    this.identityKey.encode(encoder);
    encoder.u8(3);
    return this.message.encode(encoder);
  }

  static decode(decoder: CBOR.Decoder): PreKeyMessage {
    let prekeyId = null;
    let baseKey = null;
    let identityKey = null;
    let message = null;

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          prekeyId = decoder.u16();
          break;
        case 1:
          baseKey = PublicKey.decode(decoder);
          break;
        case 2:
          identityKey = IdentityKey.decode(decoder);
          break;
        case 3:
          message = CipherMessage.decode(decoder);
          break;
        default:
          decoder.skip();
      }
    }

    prekeyId = Number(prekeyId);

    if (!isNaN(prekeyId) && baseKey && identityKey && message) {
      return PreKeyMessage.new(prekeyId, baseKey, identityKey, message);
    } else {
      throw new InputError.TypeError(`Given PreKeyMessage doesn't match expected signature.`, InputError.CODE.CASE_406);
    }
  }
}
