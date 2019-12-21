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

import {PublicKey} from '../keys/PublicKey';
import * as ClassUtil from '../util/ClassUtil';

import {DecryptError} from '../errors/DecryptError';
import {ProteusError} from '../errors/ProteusError';

import {CipherMessage} from '../message/CipherMessage';
import {Envelope} from '../message/Envelope';

import {ChainKey} from './ChainKey';
import {MessageKeys} from './MessageKeys';

export class RecvChain {
  static readonly MAX_COUNTER_GAP = 1000;
  chainKey: ChainKey;
  messageKeys: MessageKeys[];
  ratchetKey: PublicKey;

  constructor() {
    this.chainKey = new ChainKey();
    this.messageKeys = [];
    this.ratchetKey = new PublicKey();
  }

  static new(chainKey: ChainKey, publicKey: PublicKey): RecvChain {
    const recvChainInstance = ClassUtil.newInstance(RecvChain);
    recvChainInstance.chainKey = chainKey;
    recvChainInstance.ratchetKey = publicKey;
    recvChainInstance.messageKeys = [];
    return recvChainInstance;
  }

  tryMessageKeys(envelope: Envelope, cipherMessage: CipherMessage): Uint8Array {
    if (this.messageKeys[0]?.counter > cipherMessage.counter) {
      const message = `Message too old. Counter for oldest staged chain key is '${this.messageKeys[0].counter}' while message counter is '${cipherMessage.counter}'.`;
      throw new DecryptError.OutdatedMessage(message, DecryptError.CODE.CASE_208);
    }

    const index = this.messageKeys.findIndex(messageKey => messageKey.counter === cipherMessage.counter);

    if (index === -1) {
      throw new DecryptError.DuplicateMessage(undefined, DecryptError.CODE.CASE_209);
    }

    const messageKeys = this.messageKeys.splice(index, 1)[0];

    if (!envelope.verify(messageKeys.macKey)) {
      const message = `Envelope verification failed for message with counter behind. Message index is '${cipherMessage.counter}' while receive chain index is '${this.chainKey.idx}'.`;
      throw new DecryptError.InvalidSignature(message, DecryptError.CODE.CASE_210);
    }

    return messageKeys.decrypt(cipherMessage.cipherText);
  }

  stageMessageKeys(msg: CipherMessage): [ChainKey, MessageKeys, MessageKeys[]] {
    const index = msg.counter - this.chainKey.idx;
    if (index > RecvChain.MAX_COUNTER_GAP) {
      if (this.chainKey.idx === 0) {
        throw new DecryptError.TooDistantFuture(
          'Skipped too many messages at the beginning of a receive chain.',
          DecryptError.CODE.CASE_211,
        );
      }
      throw new DecryptError.TooDistantFuture(
        `Skipped too many messages within a used receive chain. Receive chain counter is '${this.chainKey.idx}'`,
        DecryptError.CODE.CASE_212,
      );
    }

    const messageKeys: MessageKeys[] = [];
    let chainKey = this.chainKey;

    for (let index = 0; index <= index - 1; index++) {
      messageKeys.push(chainKey.messageKeys());
      chainKey = chainKey.next();
    }

    const messageKey = chainKey.messageKeys();
    return [chainKey, messageKey, messageKeys];
  }

  commitMessageMeys(keys: MessageKeys[]): void {
    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError(
        `Number of message keys (${keys.length}) exceed message chain counter gap (${RecvChain.MAX_COUNTER_GAP}).`,
        ProteusError.CODE.CASE_103,
      );
    }

    const excess = this.messageKeys.length + keys.length - RecvChain.MAX_COUNTER_GAP;

    for (let index = 0; index <= excess - 1; index++) {
      this.messageKeys.shift();
    }

    keys.map(key => this.messageKeys.push(key));

    if (keys.length > RecvChain.MAX_COUNTER_GAP) {
      throw new ProteusError(
        `Skipped message keys which exceed the message chain counter gap (${RecvChain.MAX_COUNTER_GAP}).`,
        ProteusError.CODE.CASE_104,
      );
    }
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder[] {
    encoder.object(3);
    encoder.u8(0);
    this.chainKey.encode(encoder);
    encoder.u8(1);
    this.ratchetKey.encode(encoder);

    encoder.u8(2);
    encoder.array(this.messageKeys.length);
    return this.messageKeys.map(key => key.encode(encoder));
  }

  static decode(decoder: CBOR.Decoder): RecvChain {
    const self = ClassUtil.newInstance(RecvChain);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0: {
          self.chainKey = ChainKey.decode(decoder);
          break;
        }
        case 1: {
          self.ratchetKey = PublicKey.decode(decoder);
          break;
        }
        case 2: {
          self.messageKeys = [];

          let length = decoder.array();
          while (length--) {
            self.messageKeys.push(MessageKeys.decode(decoder));
          }
          break;
        }
        default: {
          decoder.skip();
        }
      }
    }

    return self;
  }
}
