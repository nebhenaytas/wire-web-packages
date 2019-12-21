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
import * as MemoryUtil from '../util/MemoryUtil';

import {DecodeError} from '../errors/DecodeError';
import {DecryptError} from '../errors/DecryptError';
import {ProteusError} from '../errors/ProteusError';
import {SessionState} from './SessionState';

import {IdentityKey} from '../keys/IdentityKey';
import {IdentityKeyPair} from '../keys/IdentityKeyPair';
import {KeyPair} from '../keys/KeyPair';
import {PreKey} from '../keys/PreKey';
import {PreKeyBundle} from '../keys/PreKeyBundle';
import {PublicKey} from '../keys/PublicKey';

import {CipherMessage} from '../message/CipherMessage';
import {Envelope} from '../message/Envelope';
import {PreKeyMessage} from '../message/PreKeyMessage';
import {SessionTag} from '../message/SessionTag';

import {PreKeyStore} from './PreKeyStore';

export interface IntermediateSessionState {
  [index: string]: {
    idx: number;
    state: SessionState;
    tag: SessionTag;
  };
}

export class Session {
  static readonly MAX_RECV_CHAINS = 5;
  static readonly MAX_SESSION_STATES = 100;

  counter = 0;
  localIdentity: IdentityKeyPair;
  pendingPrekey: (number | PublicKey)[] | null;
  remoteIdentity: IdentityKey;
  sessionStates: IntermediateSessionState;
  sessionTag: SessionTag;
  version = 1;

  constructor() {
    this.localIdentity = new IdentityKeyPair();
    this.pendingPrekey = null;
    this.remoteIdentity = new IdentityKey();
    this.sessionStates = {};
    this.sessionTag = new SessionTag();
  }

  /**
   * @param localIdentity Alice's Identity Key Pair
   * @param remotePreyKeyBundle Bob's Pre-Key Bundle
   */
  static async initFromPrekey(localIdentity: IdentityKeyPair, remotePreyKeyBundle: PreKeyBundle): Promise<Session> {
    const aliceBase = await KeyPair.new();

    const state = await SessionState.initAsAlice(localIdentity, aliceBase, remotePreyKeyBundle);

    const sessionTag = SessionTag.new();

    const sessionInstance = ClassUtil.newInstance(Session);
    sessionInstance.sessionTag = sessionTag;
    sessionInstance.localIdentity = localIdentity;
    sessionInstance.remoteIdentity = remotePreyKeyBundle.identityKey;
    sessionInstance.pendingPrekey = [remotePreyKeyBundle.prekeyId, aliceBase.publicKey];
    sessionInstance.sessionStates = {};

    sessionInstance.insertSessionState(sessionTag, state);
    return sessionInstance;
  }

  static async initFromMessage(
    ourIdentity: IdentityKeyPair,
    prekeyStore: PreKeyStore,
    envelope: Envelope,
  ): Promise<[Session, Uint8Array]> {
    const preKeyMessage = envelope.message;

    if (preKeyMessage instanceof CipherMessage) {
      throw new DecryptError.InvalidMessage(
        "Can't initialise a session from a CipherMessage.",
        DecryptError.CODE.CASE_201,
      );
    }

    if (preKeyMessage instanceof PreKeyMessage) {
      const sessionInstance = ClassUtil.newInstance(Session);
      sessionInstance.sessionTag = preKeyMessage.message.sessionTag;
      sessionInstance.localIdentity = ourIdentity;
      sessionInstance.remoteIdentity = preKeyMessage.identityKey;
      sessionInstance.pendingPrekey = null;
      sessionInstance.sessionStates = {};

      const state = await sessionInstance.newState(prekeyStore, preKeyMessage);
      const plain = await state.decrypt(envelope, preKeyMessage.message);
      sessionInstance.insertSessionState(preKeyMessage.message.sessionTag, state);

      if (preKeyMessage.prekeyId < PreKey.MAX_PREKEY_ID) {
        MemoryUtil.zeroize(await prekeyStore.loadPrekey(preKeyMessage.prekeyId));
        try {
          await prekeyStore.deletePrekey(preKeyMessage.prekeyId);
        } catch (error) {
          throw new DecryptError.PrekeyNotFound(
            `Could not delete PreKey: ${error.message}`,
            DecryptError.CODE.CASE_203,
          );
        }
      }

      return [sessionInstance, plain];
    }

    throw new DecryptError.InvalidMessage(
      'Unknown message format: The message is neither a "CipherMessage" nor a "PreKeyMessage".',
      DecryptError.CODE.CASE_202,
    );
  }

  private async newState(preKeyStore: PreKeyStore, preKeyMessage: PreKeyMessage): Promise<SessionState> {
    const preKey = await preKeyStore.loadPrekey(preKeyMessage.prekeyId);
    if (preKey) {
      return SessionState.initAsBob(
        this.localIdentity,
        preKey.keyPair,
        preKeyMessage.identityKey,
        preKeyMessage.baseKey,
      );
    }
    throw new ProteusError(
      `Unable to find PreKey ID "${preKeyMessage.prekeyId}" in PreKey store "${preKeyStore.constructor.name}".`,
      ProteusError.CODE.CASE_101,
    );
  }

  private insertSessionState(tag: SessionTag, state: SessionState): void {
    if (this.sessionStates.hasOwnProperty(tag.toString())) {
      this.sessionStates[tag.toString()].state = state;
    } else {
      if (this.counter >= Number.MAX_SAFE_INTEGER) {
        this.sessionStates = {};
        this.counter = 0;
      }

      this.sessionStates[tag.toString()] = {
        idx: this.counter,
        state: state,
        tag,
      };
      this.counter++;
    }

    if (this.sessionTag.toString() !== tag.toString()) {
      this.sessionTag = tag;
    }

    const numStates = (state: IntermediateSessionState) => Object.keys(state).length;

    if (numStates(this.sessionStates) < Session.MAX_SESSION_STATES) {
      return;
    }

    // if we get here, it means that we have more than MAX_SESSION_STATES and
    // we need to evict the oldest one.
    return this.evictOldestSessionState();
  }

  private evictOldestSessionState(): void {
    const oldest = Object.keys(this.sessionStates)
      .filter(obj => obj.toString() !== this.sessionTag.toString())
      .reduce((lowest, obj, index) => {
        return this.sessionStates[obj].idx < this.sessionStates[lowest].idx ? obj.toString() : lowest;
      });

    MemoryUtil.zeroize(this.sessionStates[oldest]);
    delete this.sessionStates[oldest];
  }

  getLocalIdentity(): IdentityKey {
    return this.localIdentity.publicKey;
  }

  /**
   * @param plaintext The plaintext which needs to be encrypted
   */
  async encrypt(plaintext: string | Uint8Array): Promise<Envelope> {
    const sessionState = this.sessionStates[this.sessionTag.toString()];

    if (!sessionState) {
      throw new ProteusError(
        `Could not find session for tag '${(this.sessionTag || '').toString()}'.`,
        ProteusError.CODE.CASE_102,
      );
    }

    return sessionState.state.encrypt(this.localIdentity.publicKey, this.pendingPrekey, this.sessionTag, plaintext);
  }

  async decrypt(prekeyStore: PreKeyStore, envelope: Envelope): Promise<Uint8Array> {
    const preKeyMessage = envelope.message;

    if (preKeyMessage instanceof CipherMessage) {
      return this.decryptCipherMessage(envelope, preKeyMessage);
    }

    if (preKeyMessage instanceof PreKeyMessage) {
      const actualFingerprint = preKeyMessage.identityKey.fingerprint();
      const expectedFingerprint = this.remoteIdentity.fingerprint();

      if (actualFingerprint !== expectedFingerprint) {
        const message = `Fingerprints do not match: We expected '${expectedFingerprint}', but received '${actualFingerprint}'.`;
        throw new DecryptError.RemoteIdentityChanged(message, DecryptError.CODE.CASE_204);
      }

      return this.decryptPrekeyMessage(envelope, preKeyMessage, prekeyStore);
    }

    throw new DecryptError('Unknown message type.', DecryptError.CODE.CASE_200);
  }

  private async decryptPrekeyMessage(
    envelope: Envelope,
    msg: PreKeyMessage,
    prekeyStore: PreKeyStore,
  ): Promise<Uint8Array> {
    try {
      const plaintext = await this.decryptCipherMessage(envelope, msg.message);
      return plaintext;
    } catch (error) {
      if (error instanceof DecryptError.InvalidSignature || error instanceof DecryptError.InvalidMessage) {
        const state = await this.newState(prekeyStore, msg);
        const plaintext = await state.decrypt(envelope, msg.message);

        if (msg.prekeyId !== PreKey.MAX_PREKEY_ID) {
          // TODO: Zeroize should be tested (and awaited) here!
          MemoryUtil.zeroize(await prekeyStore.loadPrekey(msg.prekeyId));
          await prekeyStore.deletePrekey(msg.prekeyId);
        }

        this.insertSessionState(msg.message.sessionTag, state);
        this.pendingPrekey = null;

        return plaintext;
      }
      throw error;
    }
  }

  private async decryptCipherMessage(envelope: Envelope, msg: CipherMessage): Promise<Uint8Array> {
    const serialisedState = this.sessionStates[msg.sessionTag.toString()];
    if (!serialisedState) {
      throw new DecryptError.InvalidMessage(
        `Local session not found for message session tag '${msg.sessionTag}'.`,
        DecryptError.CODE.CASE_205,
      );
    }

    // serialise and de-serialise for a deep clone
    // THIS IS IMPORTANT, DO NOT MUTATE THE SESSION STATE IN-PLACE
    // mutating in-place can lead to undefined behavior and undefined state in edge cases
    const sessionState = SessionState.deserialise(serialisedState.state.serialise());

    const plaintext = await sessionState.decrypt(envelope, msg);

    this.pendingPrekey = null;

    this.insertSessionState(msg.sessionTag, sessionState);
    return plaintext;
  }

  serialise(): ArrayBuffer {
    const encoder = new CBOR.Encoder();
    this.encode(encoder);
    return encoder.get_buffer();
  }

  static deserialise(localIdentity: IdentityKeyPair, buffer: ArrayBuffer): Session {
    const decoder = new CBOR.Decoder(buffer);
    return this.decode(localIdentity, decoder);
  }

  encode(encoder: CBOR.Encoder): void {
    encoder.object(6);
    encoder.u8(0);
    encoder.u8(this.version);
    encoder.u8(1);
    this.sessionTag.encode(encoder);
    encoder.u8(2);
    this.localIdentity.publicKey.encode(encoder);
    encoder.u8(3);
    this.remoteIdentity.encode(encoder);

    encoder.u8(4);
    if (this.pendingPrekey) {
      encoder.object(2);
      encoder.u8(0);
      encoder.u16(<number>this.pendingPrekey[0]);
      encoder.u8(1);
      (<PublicKey>this.pendingPrekey[1]).encode(encoder);
    } else {
      encoder.null();
    }

    encoder.u8(5);
    encoder.object(Object.keys(this.sessionStates).length);

    for (const index in this.sessionStates) {
      const state = this.sessionStates[index];
      state.tag.encode(encoder);
      state.state.encode(encoder);
    }
  }

  static decode(localIdentity: IdentityKeyPair, decoder: CBOR.Decoder): Session {
    const self = ClassUtil.newInstance(Session);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0: {
          self.version = decoder.u8();
          break;
        }
        case 1: {
          self.sessionTag = SessionTag.decode(decoder);
          break;
        }
        case 2: {
          const identityKey = IdentityKey.decode(decoder);
          if (localIdentity.publicKey.fingerprint() !== identityKey.fingerprint()) {
            throw new DecodeError.LocalIdentityChanged(undefined, DecodeError.CODE.CASE_300);
          }
          self.localIdentity = localIdentity;
          break;
        }
        case 3: {
          self.remoteIdentity = IdentityKey.decode(decoder);
          break;
        }
        case 4: {
          switch (decoder.optional(() => decoder.object())) {
            case null:
              self.pendingPrekey = null;
              break;
            case 2:
              self.pendingPrekey = [];
              for (let index = 0; index <= 1; ++index) {
                switch (decoder.u8()) {
                  case 0:
                    self.pendingPrekey[0] = decoder.u16();
                    break;
                  case 1:
                    self.pendingPrekey[1] = PublicKey.decode(decoder);
                    break;
                }
              }
              break;
            default:
              throw new DecodeError.InvalidType(undefined, DecodeError.CODE.CASE_301);
          }
          break;
        }
        case 5: {
          self.sessionStates = {};

          const nprops = decoder.object();

          for (let index = 0; index <= nprops - 1; index++) {
            const tag = SessionTag.decode(decoder);
            self.sessionStates[tag.toString()] = {
              idx: index,
              state: SessionState.decode(decoder),
              tag,
            };
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
