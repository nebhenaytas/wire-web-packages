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

import {KeyPair} from '../keys/KeyPair';
import * as ClassUtil from '../util/ClassUtil';
import {ChainKey} from './ChainKey';

export class SendChain {
  chainKey: ChainKey;
  ratchetKey: KeyPair;

  constructor() {
    this.chainKey = new ChainKey();
    this.ratchetKey = new KeyPair();
  }

  static new(chainKey: ChainKey, keyPair: KeyPair): SendChain {
    const sendChainInstance = ClassUtil.newInstance(SendChain);
    sendChainInstance.chainKey = chainKey;
    sendChainInstance.ratchetKey = keyPair;
    return sendChainInstance;
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(2);
    encoder.u8(0);
    this.chainKey.encode(encoder);
    encoder.u8(1);
    return this.ratchetKey.encode(encoder);
  }

  static decode(decoder: CBOR.Decoder): SendChain {
    const self = ClassUtil.newInstance(SendChain);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self.chainKey = ChainKey.decode(decoder);
          break;
        case 1:
          self.ratchetKey = KeyPair.decode(decoder);
          break;
        default:
          decoder.skip();
      }
    }

    return self;
  }
}
