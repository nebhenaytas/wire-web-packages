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

import {MacKey} from '../derived/MacKey';
import * as ClassUtil from '../util/ClassUtil';
import {Message} from './Message';

export class Envelope {
  private messageEnc: Uint8Array;
  mac: Uint8Array;
  message: Message;
  version: number;

  constructor() {
    this.messageEnc = new Uint8Array([]);
    this.mac = new Uint8Array([]);
    this.message = new Message();
    this.version = -1;
  }

  static new(macKey: MacKey, message: Message): Envelope {
    const serializedMessage = new Uint8Array(message.serialise());

    const envelopeInstance = ClassUtil.newInstance(Envelope);

    envelopeInstance.version = 1;
    envelopeInstance.mac = macKey.sign(serializedMessage);
    envelopeInstance.message = message;
    envelopeInstance.messageEnc = serializedMessage;

    Object.freeze(envelopeInstance);
    return envelopeInstance;
  }

  /** @param macKey The remote party's MacKey */
  verify(macKey: MacKey): boolean {
    return macKey.verify(this.mac, this.messageEnc);
  }

  /** @returns The serialized message envelope */
  serialise(): ArrayBuffer {
    const encoder = new CBOR.Encoder();
    this.encode(encoder);
    return encoder.get_buffer();
  }

  static deserialise(buffer: ArrayBuffer): Envelope {
    const decoder = new CBOR.Decoder(buffer);
    return Envelope.decode(decoder);
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(3);
    encoder.u8(0);
    encoder.u8(this.version);

    encoder.u8(1);
    encoder.object(1);
    encoder.u8(0);
    encoder.bytes(this.mac);

    encoder.u8(2);
    return encoder.bytes(this.messageEnc);
  }

  static decode(decoder: CBOR.Decoder): Envelope {
    const envelopeInstance = ClassUtil.newInstance(Envelope);
    const nprops = decoder.object();

    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0: {
          envelopeInstance.version = decoder.u8();
          break;
        }
        case 1: {
          const npropsMac = decoder.object();

          for (let subindex = 0; subindex <= npropsMac - 1; subindex++) {
            switch (decoder.u8()) {
              case 0:
                envelopeInstance.mac = new Uint8Array(decoder.bytes());
                break;
              default:
                decoder.skip();
            }
          }

          break;
        }
        case 2: {
          envelopeInstance.messageEnc = new Uint8Array(decoder.bytes());
          break;
        }
        default: {
          decoder.skip();
        }
      }
    }

    envelopeInstance.message = Message.deserialise(envelopeInstance.messageEnc.buffer);

    Object.freeze(envelopeInstance);
    return envelopeInstance;
  }
}
