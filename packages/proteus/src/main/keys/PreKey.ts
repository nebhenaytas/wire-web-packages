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

import {InputError} from '../errors/InputError';

import {KeyPair} from './KeyPair';

/**
 * Pre-generated (and regularly refreshed) pre-keys.
 * A Pre-Shared Key contains the public long-term identity and ephemeral handshake keys for the initial triple DH.
 */
export class PreKey {
  static readonly MAX_PREKEY_ID = 0xffff;
  keyId: number;
  keyPair: KeyPair;
  version: number;

  constructor() {
    this.keyId = -1;
    this.keyPair = new KeyPair();
    this.version = -1;
  }

  static async new(preKeyId: number): Promise<PreKey> {
    this.validatePreKeyId(preKeyId);

    const preKeyInstance = ClassUtil.newInstance(PreKey);

    preKeyInstance.version = 1;
    preKeyInstance.keyId = preKeyId;
    preKeyInstance.keyPair = await KeyPair.new();
    return preKeyInstance;
  }

  static validatePreKeyId(preKeyId: number): void {
    if (preKeyId === undefined) {
      throw new InputError.TypeError('PreKey ID is undefined.', InputError.CODE.CASE_404);
    }

    if (typeof preKeyId === 'string') {
      throw new InputError.TypeError(`PreKey ID "${preKeyId}" is a string.`, InputError.CODE.CASE_403);
    }

    if (preKeyId % 1 !== 0) {
      throw new InputError.TypeError(`PreKey ID "${preKeyId}" is a floating-point number.`, InputError.CODE.CASE_403);
    }

    if (preKeyId < 0 || preKeyId > PreKey.MAX_PREKEY_ID) {
      const message = `PreKey ID (${preKeyId}) must be between or equal to 0 and ${PreKey.MAX_PREKEY_ID}.`;
      throw new InputError.RangeError(message, InputError.CODE.CASE_400);
    }
  }

  static lastResort(): Promise<PreKey> {
    return PreKey.new(PreKey.MAX_PREKEY_ID);
  }

  static async generatePrekeys(start: number, size: number): Promise<PreKey[]> {
    this.validatePreKeyId(start);
    this.validatePreKeyId(size);

    if (size === 0) {
      return [];
    }

    return Promise.all(
      Array.from({length: size}).map((_, index) => PreKey.new((start + index) % PreKey.MAX_PREKEY_ID)),
    );
  }

  serialise(): ArrayBuffer {
    const encoder = new CBOR.Encoder();
    this.encode(encoder);
    return encoder.get_buffer();
  }

  static deserialise(buffer: ArrayBuffer): PreKey {
    return PreKey.decode(new CBOR.Decoder(buffer));
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(3);
    encoder.u8(0);
    encoder.u8(this.version);
    encoder.u8(1);
    encoder.u16(this.keyId);
    encoder.u8(2);
    return this.keyPair.encode(encoder);
  }

  static decode(decoder: CBOR.Decoder): PreKey {
    const self = ClassUtil.newInstance(PreKey);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self.version = decoder.u8();
          break;
        case 1:
          self.keyId = decoder.u16();
          break;
        case 2:
          self.keyPair = KeyPair.decode(decoder);
          break;
        default:
          decoder.skip();
      }
    }

    return self;
  }
}
