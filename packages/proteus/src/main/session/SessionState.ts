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

import * as ArrayUtil from '../util/ArrayUtil';
import * as ClassUtil from '../util/ClassUtil';
import * as MemoryUtil from '../util/MemoryUtil';

import {DecryptError} from '../errors/DecryptError';

import {DerivedSecrets} from '../derived/DerivedSecrets';

import {IdentityKey} from '../keys/IdentityKey';
import {IdentityKeyPair} from '../keys/IdentityKeyPair';
import {KeyPair} from '../keys/KeyPair';
import {PreKeyBundle} from '../keys/PreKeyBundle';
import {PublicKey} from '../keys/PublicKey';

import {CipherMessage} from '../message/CipherMessage';
import {Envelope} from '../message/Envelope';
import {Message} from '../message/Message';
import {PreKeyMessage} from '../message/PreKeyMessage';
import {SessionTag} from '../message/SessionTag';

import {ChainKey} from './ChainKey';
import {RecvChain} from './RecvChain';
import {RootKey} from './RootKey';
import {SendChain} from './SendChain';
import {Session} from './Session';

export class SessionState {
  prevCounter: number;
  recvChains: RecvChain[];
  rootKey: RootKey;
  sendChain: SendChain;

  constructor() {
    this.prevCounter = -1;
    this.recvChains = [];
    this.rootKey = new RootKey();
    this.sendChain = new SendChain();
  }

  static async initAsAlice(
    aliceIdentityPair: IdentityKeyPair,
    aliceBase: IdentityKeyPair | KeyPair,
    bobPreyKeyBundle: PreKeyBundle,
  ): Promise<SessionState> {
    const masterKey = ArrayUtil.concatenateArrayBuffers([
      aliceIdentityPair.secretKey.sharedSecret(bobPreyKeyBundle.publicKey),
      aliceBase.secretKey.sharedSecret(bobPreyKeyBundle.identityKey.publicKey),
      aliceBase.secretKey.sharedSecret(bobPreyKeyBundle.publicKey),
    ]);

    const derivedSecrets = DerivedSecrets.kdfWithoutSalt(masterKey, 'handshake');
    MemoryUtil.zeroize(masterKey);

    const rootkey = RootKey.fromCipherKey(derivedSecrets.cipherKey);
    const chainkey = ChainKey.fromMacKey(derivedSecrets.macKey, 0);

    const recvChains = [RecvChain.new(chainkey, bobPreyKeyBundle.publicKey)];

    const sendRatchet = await KeyPair.new();
    const [rok, chk] = rootkey.dhRatchet(sendRatchet, bobPreyKeyBundle.publicKey);
    const sendChain = SendChain.new(chk, sendRatchet);

    const sessionStateInstance = ClassUtil.newInstance(SessionState);
    sessionStateInstance.recvChains = recvChains;
    sessionStateInstance.sendChain = sendChain;
    sessionStateInstance.rootKey = rok;
    sessionStateInstance.prevCounter = 0;
    return sessionStateInstance;
  }

  static initAsBob(
    bobIdentity: IdentityKeyPair,
    bobPrekey: KeyPair,
    aliceIdentityKey: IdentityKey,
    aliceBase: PublicKey,
  ): SessionState {
    const masterKey = ArrayUtil.concatenateArrayBuffers([
      bobPrekey.secretKey.sharedSecret(aliceIdentityKey.publicKey),
      bobIdentity.secretKey.sharedSecret(aliceBase),
      bobPrekey.secretKey.sharedSecret(aliceBase),
    ]);

    const derivedSecrets = DerivedSecrets.kdfWithoutSalt(masterKey, 'handshake');
    MemoryUtil.zeroize(masterKey);

    const rootkey = RootKey.fromCipherKey(derivedSecrets.cipherKey);
    const chainkey = ChainKey.fromMacKey(derivedSecrets.macKey, 0);
    const sendChainInstance = SendChain.new(chainkey, bobPrekey);

    const sessionStateInstance = ClassUtil.newInstance(SessionState);
    sessionStateInstance.recvChains = [];
    sessionStateInstance.sendChain = sendChainInstance;
    sessionStateInstance.rootKey = rootkey;
    sessionStateInstance.prevCounter = 0;
    return sessionStateInstance;
  }

  async ratchet(ratchetKey: PublicKey): Promise<void> {
    const newRatchet = await KeyPair.new();

    const [recvRootKey, recvChainKey] = this.rootKey.dhRatchet(this.sendChain.ratchetKey, ratchetKey);

    const [sendRootKey, sendChainKey] = recvRootKey.dhRatchet(newRatchet, ratchetKey);

    const recvChain = RecvChain.new(recvChainKey, ratchetKey);
    const sendChain = SendChain.new(sendChainKey, newRatchet);

    this.rootKey = sendRootKey;
    this.prevCounter = this.sendChain.chainKey.idx;
    this.sendChain = sendChain;

    this.recvChains.unshift(recvChain);

    if (this.recvChains.length > Session.MAX_RECV_CHAINS) {
      for (let index = Session.MAX_RECV_CHAINS; index < this.recvChains.length; index++) {
        MemoryUtil.zeroize(this.recvChains[index]);
      }

      this.recvChains = this.recvChains.slice(0, Session.MAX_RECV_CHAINS);
    }
  }

  /**
   * @param identityKey Public identity key of the local identity key pair
   * @param pendingPreykey Pending pre-key
   * @param sessionTag Session tag
   * @param plaintext The plaintext to encrypt
   */
  encrypt(
    identityKey: IdentityKey,
    pendingPreykey: (number | PublicKey)[] | null,
    sessionTag: SessionTag,
    plaintext: string | Uint8Array,
  ): Envelope {
    const msgkeys = this.sendChain.chainKey.messageKeys();

    let message: Message = CipherMessage.new(
      sessionTag,
      this.sendChain.chainKey.idx,
      this.prevCounter,
      this.sendChain.ratchetKey.publicKey,
      msgkeys.encrypt(plaintext),
    );

    if (pendingPreykey) {
      message = PreKeyMessage.new(
        pendingPreykey[0] as number,
        pendingPreykey[1] as PublicKey,
        identityKey,
        message as CipherMessage,
      );
    }

    const envelopeInstance = Envelope.new(msgkeys.macKey, message);
    this.sendChain.chainKey = this.sendChain.chainKey.next();
    return envelopeInstance;
  }

  async decrypt(envelope: Envelope, msg: CipherMessage): Promise<Uint8Array> {
    let index = this.recvChains.findIndex(chain => chain.ratchetKey.fingerprint() === msg.ratchetKey.fingerprint());

    if (index === -1) {
      await this.ratchet(msg.ratchetKey);
      index = 0;
    }

    const receiveChain = this.recvChains[index];

    if (msg.counter < receiveChain.chainKey.idx) {
      return receiveChain.tryMessageKeys(envelope, msg);
    } else if (msg.counter == receiveChain.chainKey.idx) {
      const messageKeys = receiveChain.chainKey.messageKeys();

      if (!envelope.verify(messageKeys.macKey)) {
        throw new DecryptError.InvalidSignature(
          `Envelope verification failed for message with counters in sync at '${msg.counter}'. The received message was possibly encrypted for another client.`,
          DecryptError.CODE.CASE_206,
        );
      }

      const plain = messageKeys.decrypt(msg.cipherText);
      receiveChain.chainKey = receiveChain.chainKey.next();
      return plain;
    } else {
      const [chainKey, messageKey, messageKeys] = receiveChain.stageMessageKeys(msg);

      if (!envelope.verify(messageKey.macKey)) {
        throw new DecryptError.InvalidSignature(
          `Envelope verification failed for message with counter ahead. Message index is '${msg.counter}' while receive chain index is '${receiveChain.chainKey.idx}'.`,
          DecryptError.CODE.CASE_207,
        );
      }

      const plain = messageKey.decrypt(msg.cipherText);

      receiveChain.chainKey = chainKey.next();
      receiveChain.commitMessageMeys(messageKeys);

      return plain;
    }
  }

  serialise(): ArrayBuffer {
    const encoder = new CBOR.Encoder();
    this.encode(encoder);
    return encoder.get_buffer();
  }

  static deserialise(buffer: ArrayBuffer): SessionState {
    return SessionState.decode(new CBOR.Decoder(buffer));
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(4);
    encoder.u8(0);
    encoder.array(this.recvChains.length);
    this.recvChains.map(rch => rch.encode(encoder));
    encoder.u8(1);
    this.sendChain.encode(encoder);
    encoder.u8(2);
    this.rootKey.encode(encoder);
    encoder.u8(3);
    return encoder.u32(this.prevCounter);
  }

  static decode(decoder: CBOR.Decoder): SessionState {
    const self = ClassUtil.newInstance(SessionState);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0: {
          self.recvChains = [];
          let length = decoder.array();
          while (length--) {
            self.recvChains.push(RecvChain.decode(decoder));
          }
          break;
        }
        case 1: {
          self.sendChain = SendChain.decode(decoder);
          break;
        }
        case 2: {
          self.rootKey = RootKey.decode(decoder);
          break;
        }
        case 3: {
          self.prevCounter = decoder.u32();
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
