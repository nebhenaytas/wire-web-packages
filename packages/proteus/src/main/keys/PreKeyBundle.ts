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
import * as sodium from 'libsodium-wrappers-sumo';

import * as ClassUtil from '../util/ClassUtil';
import {IdentityKey} from './IdentityKey';
import {IdentityKeyPair} from './IdentityKeyPair';
import {PreKey} from './PreKey';
import {PreKeyAuth} from './PreKeyAuth';
import {PublicKey} from './PublicKey';

export interface SerialisedJSON {
  id: number;
  key: string;
}

export class PreKeyBundle {
  version: number;
  prekeyId: number;
  publicKey: PublicKey;
  identityKey: IdentityKey;
  signature: Uint8Array | null | undefined;

  constructor() {
    this.version = -1;
    this.prekeyId = -1;
    this.publicKey = new PublicKey();
    this.identityKey = new IdentityKey();
    this.signature = null;
  }

  static new(publicIdentityKey: IdentityKey, prekey: PreKey): PreKeyBundle {
    const preKeyBundleInstance = ClassUtil.newInstance(PreKeyBundle);

    preKeyBundleInstance.version = 1;
    preKeyBundleInstance.prekeyId = prekey.keyId;
    preKeyBundleInstance.publicKey = prekey.keyPair.publicKey;
    preKeyBundleInstance.identityKey = publicIdentityKey;
    preKeyBundleInstance.signature = null;

    return preKeyBundleInstance;
  }

  static signed(identityPair: IdentityKeyPair, prekey: PreKey): PreKeyBundle {
    const ratchetKey = prekey.keyPair.publicKey;
    const signature = identityPair.secretKey.sign(ratchetKey.pubEdward);

    const preKeyBundleInstance = ClassUtil.newInstance(PreKeyBundle);

    preKeyBundleInstance.version = 1;
    preKeyBundleInstance.prekeyId = prekey.keyId;
    preKeyBundleInstance.publicKey = ratchetKey;
    preKeyBundleInstance.identityKey = identityPair.publicKey;
    preKeyBundleInstance.signature = signature;

    return preKeyBundleInstance;
  }

  verify(): PreKeyAuth {
    if (!this.signature) {
      return PreKeyAuth.UNKNOWN;
    }

    if (this.identityKey.publicKey.verify(this.signature, this.publicKey.pubEdward)) {
      return PreKeyAuth.VALID;
    }

    return PreKeyAuth.INVALID;
  }

  serialise(): ArrayBuffer {
    const encoder = new CBOR.Encoder();
    this.encode(encoder);
    return encoder.get_buffer();
  }

  serialisedJson(): SerialisedJSON {
    return {
      id: this.prekeyId,
      key: sodium.to_base64(new Uint8Array(this.serialise()), sodium.base64_variants.ORIGINAL),
    };
  }

  static deserialise(buffer: ArrayBuffer): PreKeyBundle {
    return PreKeyBundle.decode(new CBOR.Decoder(buffer));
  }

  encode(encoder: CBOR.Encoder): CBOR.Encoder {
    encoder.object(5);
    encoder.u8(0);
    encoder.u8(this.version);
    encoder.u8(1);
    encoder.u16(this.prekeyId);
    encoder.u8(2);
    this.publicKey.encode(encoder);
    encoder.u8(3);
    this.identityKey.encode(encoder);

    encoder.u8(4);
    if (!this.signature) {
      return encoder.null();
    }
    return encoder.bytes(this.signature);
  }

  static decode(decoder: CBOR.Decoder): PreKeyBundle {
    const self = ClassUtil.newInstance(PreKeyBundle);

    const nprops = decoder.object();
    for (let index = 0; index <= nprops - 1; index++) {
      switch (decoder.u8()) {
        case 0:
          self.version = decoder.u8();
          break;
        case 1:
          self.prekeyId = decoder.u16();
          break;
        case 2:
          self.publicKey = PublicKey.decode(decoder);
          break;
        case 3:
          self.identityKey = IdentityKey.decode(decoder);
          break;
        case 4:
          self.signature = decoder.optional(() => new Uint8Array(decoder.bytes()));
          break;
        default:
          decoder.skip();
      }
    }

    return self;
  }
}
