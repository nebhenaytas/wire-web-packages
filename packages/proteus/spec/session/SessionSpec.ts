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

// tslint:disable:no-magic-numbers

import * as Proteus from '@wireapp/proteus';
import * as sodium from 'libsodium-wrappers-sumo';

const assertSerialiseDeserialise = (localIdentity: Proteus.keys.IdentityKeyPair, session: Proteus.session.Session) => {
  const bytes = session.serialise();

  const deser = Proteus.session.Session.deserialise(localIdentity, bytes);
  const deserBytes = deser.serialise();

  expect(sodium.to_hex(new Uint8Array(bytes))).toEqual(sodium.to_hex(new Uint8Array(deserBytes)));
};

const assertInitFromMessage = async (
  identity: Proteus.keys.IdentityKeyPair,
  store: Proteus.session.PreKeyStore,
  envelope: Proteus.message.Envelope,
  expected: string,
) => {
  const [session, message] = await Proteus.session.Session.initFromMessage(identity, store, envelope);
  expect(sodium.to_string(message)).toBe(expected);
  return session;
};

class TestStore extends Proteus.session.PreKeyStore {
  private readonly prekeys: Proteus.keys.PreKey[];

  constructor(prekeys: Proteus.keys.PreKey[]) {
    super();
    this.prekeys = prekeys;
  }

  async loadPrekey(prekeyId: number): Promise<Proteus.keys.PreKey> {
    return this.prekeys.find(prekey => prekey.keyId === prekeyId)!;
  }

  async loadPrekeys(): Promise<Proteus.keys.PreKey[]> {
    return this.prekeys;
  }

  async deletePrekey(prekeyId: number): Promise<number> {
    const matches = this.prekeys.filter(prekey => prekey.keyId === prekeyId);
    delete matches[0];
    return prekeyId;
  }
}

beforeAll(async () => {
  await sodium.ready;
});

describe('Session', () => {
  describe('Setup', () => {
    it('generates a session from a prekey message', async () => {
      const preKeys = await Proteus.keys.PreKey.generatePrekeys(0, 10);
      const bobStore = new TestStore(preKeys);

      const alice = await Proteus.keys.IdentityKeyPair.new();
      const bob = await Proteus.keys.IdentityKeyPair.new();
      const preKey = await bobStore.loadPrekey(0);
      const bobPrekeyBundle = Proteus.keys.PreKeyBundle.new(bob.publicKey, preKey);
      const aliceToBob = await Proteus.session.Session.initFromPrekey(alice, bobPrekeyBundle);

      const plaintext = 'Hello Bob!';

      const preKeyMessage = await aliceToBob.encrypt(plaintext);

      const envelope = Proteus.message.Envelope.deserialise(preKeyMessage.serialise());

      const [bobToAlice, decrypted] = await Proteus.session.Session.initFromMessage(bob, bobStore, envelope);

      expect(sodium.to_string(decrypted)).toBe(plaintext);
      expect(bobToAlice).toBeDefined();
    });
  });

  describe('Serialisation', () => {
    it('can be serialised and deserialised to/from CBOR', async () => {
      const [aliceIdent, bobIdent] = await Promise.all([
        Proteus.keys.IdentityKeyPair.new(),
        Proteus.keys.IdentityKeyPair.new(),
      ]);
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains.length).toEqual(1);
      expect(alice.pendingPrekey!.length).toBe(2);

      assertSerialiseDeserialise(aliceIdent, alice);
    });

    it('encrypts and decrypts messages', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains.length).toBe(1);

      const helloBob = await alice.encrypt('Hello Bob!');
      const helloBobDelayed = await alice.encrypt('Hello delay!');

      expect(Object.keys(alice.sessionStates).length).toBe(1);
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains.length).toBe(1);

      const bob = await assertInitFromMessage(bobIdent, bobStore, helloBob, 'Hello Bob!');

      expect(Object.keys(bob.sessionStates).length).toBe(1);
      expect(bob.sessionStates[bob.sessionTag.toString()].state.recvChains.length).toBe(1);

      const helloAlice = await bob.encrypt('Hello Alice!');

      expect(alice.pendingPrekey!.length).toBe(2);

      expect(sodium.to_string(await alice.decrypt(aliceStore, helloAlice))).toBe('Hello Alice!');

      expect(alice.pendingPrekey).toBe(null);
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains.length).toBe(2);
      expect(alice.remoteIdentity.fingerprint()).toBe(bob.localIdentity.publicKey.fingerprint());

      const pingBob_1 = await alice.encrypt('Ping1!');
      const pingBob_2 = await alice.encrypt('Ping2!');

      expect(alice.sessionStates[alice.sessionTag.toString()].state.prevCounter).toBe(2);

      expect(pingBob_1.message).toEqual(jasmine.any(Proteus.message.CipherMessage));
      expect(pingBob_2.message).toEqual(jasmine.any(Proteus.message.CipherMessage));

      expect(sodium.to_string(await bob.decrypt(bobStore, pingBob_1))).toBe('Ping1!');

      expect(bob.sessionStates[bob.sessionTag.toString()].state.recvChains.length).toBe(2);

      expect(sodium.to_string(await bob.decrypt(bobStore, pingBob_2))).toBe('Ping2!');

      expect(bob.sessionStates[bob.sessionTag.toString()].state.recvChains.length).toBe(2);

      const pongAlice = await bob.encrypt('Pong!');
      expect(sodium.to_string(await alice.decrypt(aliceStore, pongAlice))).toBe('Pong!');

      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains.length).toBe(3);
      expect(alice.sessionStates[alice.sessionTag.toString()].state.prevCounter).toBe(2);

      const delayDecrypted = await bob.decrypt(bobStore, helloBobDelayed);
      expect(sodium.to_string(delayDecrypted)).toBe('Hello delay!');

      expect(bob.sessionStates[bob.sessionTag.toString()].state.recvChains.length).toBe(2);
      expect(bob.sessionStates[bob.sessionTag.toString()].state.prevCounter).toBe(1);

      assertSerialiseDeserialise(aliceIdent, alice);
      assertSerialiseDeserialise(bobIdent, bob);
    });

    it('limits the number of receive chains', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      const helloBob = await alice.encrypt('Hello Bob!');

      const bob = await assertInitFromMessage(bobIdent, bobStore, helloBob, 'Hello Bob!');

      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains.length).toBe(1);
      expect(bob.sessionStates[bob.sessionTag.toString()].state.recvChains.length).toBe(1);

      await Promise.all(
        Array.from({length: Proteus.session.Session.MAX_RECV_CHAINS * 2}, async () => {
          const bobToAlice = await bob.encrypt('ping');
          expect(sodium.to_string(await alice.decrypt(aliceStore, bobToAlice))).toBe('ping');

          const aliceToBob = await alice.encrypt('pong');
          expect(sodium.to_string(await bob.decrypt(bobStore, aliceToBob))).toBe('pong');

          expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains.length).not.toBeGreaterThan(
            Proteus.session.Session.MAX_RECV_CHAINS,
          );

          expect(bob.sessionStates[bob.sessionTag.toString()].state.recvChains.length).not.toBeGreaterThan(
            Proteus.session.Session.MAX_RECV_CHAINS,
          );
        }),
      );
    });

    it('handles a counter mismatch', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      const message = await alice.encrypt('Hello Bob!');

      const bob = await assertInitFromMessage(bobIdent, bobStore, message, 'Hello Bob!');
      const ciphertexts = await Promise.all(
        ['Hello1', 'Hello2', 'Hello3', 'Hello4', 'Hello5'].map(text => bob.encrypt(text)),
      );

      expect(sodium.to_string(await alice.decrypt(aliceStore, ciphertexts[1]))).toBe('Hello2');
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains[0].messageKeys.length).toBe(1);

      assertSerialiseDeserialise(aliceIdent, alice);

      expect(sodium.to_string(await alice.decrypt(aliceStore, ciphertexts[0]))).toBe('Hello1');
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains[0].messageKeys.length).toBe(0);

      expect(sodium.to_string(await alice.decrypt(aliceStore, ciphertexts[2]))).toBe('Hello3');
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains[0].messageKeys.length).toBe(0);

      expect(sodium.to_string(await alice.decrypt(aliceStore, ciphertexts[4]))).toBe('Hello5');
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains[0].messageKeys.length).toBe(1);

      expect(sodium.to_string(await alice.decrypt(aliceStore, ciphertexts[3]))).toBe('Hello4');
      expect(alice.sessionStates[alice.sessionTag.toString()].state.recvChains[0].messageKeys.length).toBe(0);

      await Promise.all(
        ciphertexts.map(async text => {
          try {
            await alice.decrypt(aliceStore, text);
            fail();
          } catch (error) {
            expect(error instanceof Proteus.errors.DecryptError.DuplicateMessage).toBe(true);
            expect(error.code).toBe(Proteus.errors.DecryptError.CODE.CASE_209);
          }
        }),
      );

      assertSerialiseDeserialise(aliceIdent, alice);
      assertSerialiseDeserialise(bobIdent, bob);
    });

    it('handles multiple prekey messages', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      const helloBob1 = await alice.encrypt('Hello Bob1!');
      const helloBob2 = await alice.encrypt('Hello Bob2!');
      const helloBob3 = await alice.encrypt('Hello Bob3!');

      const [bob, decrypted] = await Proteus.session.Session.initFromMessage(bobIdent, bobStore, helloBob1);

      expect(decrypted).toBeDefined();

      expect(Object.keys(bob.sessionStates).length).toBe(1);
      expect(sodium.to_string(await bob.decrypt(aliceStore, helloBob2))).toBe('Hello Bob2!');
      expect(Object.keys(bob.sessionStates).length).toBe(1);
      expect(sodium.to_string(await bob.decrypt(aliceStore, helloBob3))).toBe('Hello Bob3!');
      expect(Object.keys(bob.sessionStates).length).toBe(1);

      assertSerialiseDeserialise(aliceIdent, alice);
      assertSerialiseDeserialise(bobIdent, bob);
    });

    it('handles simultaneous prekey messages', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alicePrekey = await aliceStore.loadPrekey(0);
      const aliceBundle = Proteus.keys.PreKeyBundle.new(aliceIdent.publicKey, alicePrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      const helloBobEncrypted = await alice.encrypt('Hello Bob!');

      const bob = await Proteus.session.Session.initFromPrekey(bobIdent, aliceBundle);
      const helloAlice = await bob.encrypt('Hello Alice!');

      expect(alice.sessionTag.toString()).not.toEqual(bob.sessionTag.toString());
      expect(helloAlice).toBeDefined();

      const helloBobDecrypted = await bob.decrypt(bobStore, helloBobEncrypted);
      expect(sodium.to_string(helloBobDecrypted)).toBe('Hello Bob!');
      expect(Object.keys(bob.sessionStates).length).toBe(2);

      expect(sodium.to_string(await alice.decrypt(aliceStore, helloAlice))).toBe('Hello Alice!');
      expect(Object.keys(alice.sessionStates).length).toBe(2);

      const messageAlice = await alice.encrypt('That was fast!');
      expect(sodium.to_string(await bob.decrypt(bobStore, messageAlice))).toBe('That was fast!');

      const messageBob = await bob.encrypt(':-)');

      expect(sodium.to_string(await alice.decrypt(aliceStore, messageBob))).toBe(':-)');
      expect(alice.sessionTag.toString()).toEqual(bob.sessionTag.toString());

      assertSerialiseDeserialise(aliceIdent, alice);
      assertSerialiseDeserialise(bobIdent, bob);
    });

    it('handles simultaneous repeated messages', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alicePrekey = await aliceStore.loadPrekey(0);
      const aliceBundle = Proteus.keys.PreKeyBundle.new(aliceIdent.publicKey, alicePrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      const helloBobPlaintext = 'Hello Bob!';
      const helloBobEncrypted = await alice.encrypt(helloBobPlaintext);

      const bob = await Proteus.session.Session.initFromPrekey(bobIdent, aliceBundle);
      const helloAlicePlaintext = 'Hello Alice!';
      const helloAliceEncrypted = await bob.encrypt(helloAlicePlaintext);

      expect(alice.sessionTag.toString()).not.toEqual(bob.sessionTag.toString());

      const helloBobDecrypted = await bob.decrypt(bobStore, helloBobEncrypted);
      expect(sodium.to_string(helloBobDecrypted)).toBe(helloBobPlaintext);

      const helloAliceDecrypted = await alice.decrypt(aliceStore, helloAliceEncrypted);
      expect(sodium.to_string(helloAliceDecrypted)).toBe(helloAlicePlaintext);

      const echoBob1Plaintext = 'Echo Bob1!';
      const echoBob1Encrypted = await alice.encrypt(echoBob1Plaintext);

      const echoAlice1Plaintext = 'Echo Alice1!';
      const echoAlice1Encrypted = await bob.encrypt(echoAlice1Plaintext);

      const echoBob1Decrypted = await bob.decrypt(bobStore, echoBob1Encrypted);
      expect(sodium.to_string(echoBob1Decrypted)).toBe(echoBob1Plaintext);
      expect(Object.keys(bob.sessionStates).length).toBe(2);

      const echoAlice1Decrypted = await alice.decrypt(aliceStore, echoAlice1Encrypted);
      expect(sodium.to_string(echoAlice1Decrypted)).toBe(echoAlice1Plaintext);
      expect(Object.keys(alice.sessionStates).length).toBe(2);

      const echoBob2Plaintext = 'Echo Bob2!';
      const echoBob2Encrypted = await alice.encrypt(echoBob2Plaintext);

      const echoAlice2Plaintext = 'Echo Alice2!';
      const echoAlice2Encrypted = await bob.encrypt(echoAlice2Plaintext);

      const echoBob2Decrypted = await bob.decrypt(bobStore, echoBob2Encrypted);
      expect(sodium.to_string(echoBob2Decrypted)).toBe(echoBob2Plaintext);
      expect(Object.keys(bob.sessionStates).length).toBe(2);

      const echoAlice2Decrypted = await alice.decrypt(aliceStore, echoAlice2Encrypted);
      expect(sodium.to_string(echoAlice2Decrypted)).toBe(echoAlice2Plaintext);
      expect(Object.keys(alice.sessionStates).length).toBe(2);

      expect(alice.sessionTag.toString()).not.toEqual(bob.sessionTag.toString());

      const stopItPlaintext = 'Stop it!';
      const stopItEncrypted = await alice.encrypt(stopItPlaintext);

      const stopItDecrypted = await bob.decrypt(bobStore, stopItEncrypted);
      expect(sodium.to_string(stopItDecrypted)).toBe(stopItPlaintext);
      expect(Object.keys(bob.sessionStates).length).toBe(2);

      const okPlaintext = 'OK';
      const okEncrypted = await bob.encrypt(okPlaintext);

      const okDecrypted = await alice.decrypt(aliceStore, okEncrypted);
      expect(sodium.to_string(okDecrypted)).toBe(okPlaintext);
      expect(Object.keys(alice.sessionStates).length).toBe(2);

      expect(alice.sessionTag.toString()).toEqual(bob.sessionTag.toString());

      assertSerialiseDeserialise(aliceIdent, alice);
      assertSerialiseDeserialise(bobIdent, bob);
    });

    it('fails retry init from message', async () => {
      try {
        const aliceIdent = await Proteus.keys.IdentityKeyPair.new();

        const bobIdent = await Proteus.keys.IdentityKeyPair.new();
        const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

        const bobPrekey = await bobStore.loadPrekey(0);
        const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

        const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);

        const helloBobPlaintext = 'Hello Bob!';
        const helloBobEncrypted = await alice.encrypt(helloBobPlaintext);

        await assertInitFromMessage(bobIdent, bobStore, helloBobEncrypted, helloBobPlaintext);

        await Proteus.session.Session.initFromMessage(bobIdent, bobStore, helloBobEncrypted);

        fail();
      } catch (error) {
        expect(error instanceof Proteus.errors.DecryptError).toBe(true);
        expect(error.code).toBe(Proteus.errors.DecryptError.CODE.CASE_206);
      }
    });

    it('skips message keys', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);

      const helloBobPlaintext = 'Hello Bob!';
      const helloBobEncrypted = await alice.encrypt(helloBobPlaintext);

      let state = alice.sessionStates[alice.sessionTag.toString()].state;
      expect(state.recvChains.length).toBe(1);
      expect(state.recvChains[0].chainKey.idx).toBe(0);
      expect(state.sendChain.chainKey.idx).toBe(1);
      expect(state.recvChains[0].messageKeys.length).toBe(0);

      const bob = await assertInitFromMessage(bobIdent, bobStore, helloBobEncrypted, helloBobPlaintext);

      state = bob.sessionStates[bob.sessionTag.toString()].state;
      expect(state.recvChains.length).toBe(1);
      expect(state.recvChains[0].chainKey.idx).toBe(1);
      expect(state.sendChain.chainKey.idx).toBe(0);
      expect(state.recvChains[0].messageKeys.length).toBe(0);

      const helloAlice0Plaintext = 'Hello0';
      const helloAlice0Encrypted = await bob.encrypt(helloAlice0Plaintext);

      await bob.encrypt('Hello1'); // unused result

      const helloAlice2Plaintext = 'Hello2';
      const helloAlice2Encrypted = await bob.encrypt(helloAlice2Plaintext);

      const helloAlice2Decrypted = await alice.decrypt(aliceStore, helloAlice2Encrypted);
      expect(sodium.to_string(helloAlice2Decrypted)).toBe(helloAlice2Plaintext);

      // Alice has two skipped message keys in her new receive chain:
      state = alice.sessionStates[alice.sessionTag.toString()].state;
      expect(state.recvChains.length).toBe(2);
      expect(state.recvChains[0].chainKey.idx).toBe(3);
      expect(state.sendChain.chainKey.idx).toBe(0);
      expect(state.recvChains[0].messageKeys.length).toBe(2);
      expect(state.recvChains[0].messageKeys[0].counter).toBe(0);
      expect(state.recvChains[0].messageKeys[1].counter).toBe(1);

      const helloBob0Plaintext = 'Hello0';
      const helloBob0Encrypted = await alice.encrypt(helloBob0Plaintext);

      const helloBob0Decrypted = await bob.decrypt(bobStore, helloBob0Encrypted);
      expect(sodium.to_string(helloBob0Decrypted)).toBe(helloBob0Plaintext);

      // For Bob everything is normal still. A new message from Alice means a
      // new receive chain has been created and again no skipped message keys.

      state = bob.sessionStates[bob.sessionTag.toString()].state;
      expect(state.recvChains.length).toBe(2);
      expect(state.recvChains[0].chainKey.idx).toBe(1);
      expect(state.sendChain.chainKey.idx).toBe(0);
      expect(state.recvChains[0].messageKeys.length).toBe(0);

      const helloAlice0Decrypted = await alice.decrypt(aliceStore, helloAlice0Encrypted);
      expect(sodium.to_string(helloAlice0Decrypted)).toBe(helloAlice0Plaintext);

      // Alice received the first of the two missing messages. Therefore
      // only one message key is still skipped (counter value = 1).

      state = alice.sessionStates[alice.sessionTag.toString()].state;
      expect(state.recvChains.length).toBe(2);
      expect(state.recvChains[0].messageKeys.length).toBe(1);
      expect(state.recvChains[0].messageKeys[0].counter).toBe(1);

      const helloAgain0Plaintext = 'Again0';
      const helloAgain0Encrypted = await bob.encrypt(helloAgain0Plaintext);

      const helloAgain1Plaintext = 'Again1';
      const helloAgain1Encrypted = await bob.encrypt(helloAgain1Plaintext);

      const helloAgain1Decrypted = await alice.decrypt(aliceStore, helloAgain1Encrypted);
      expect(sodium.to_string(helloAgain1Decrypted)).toBe(helloAgain1Plaintext);

      // Alice received the first of the two missing messages. Therefore
      // only one message key is still skipped (counter value = 1).

      state = alice.sessionStates[alice.sessionTag.toString()].state;
      expect(state.recvChains.length).toBe(3);
      expect(state.recvChains[0].messageKeys.length).toBe(1);
      expect(state.recvChains[1].messageKeys.length).toBe(1);
      expect(state.recvChains[0].messageKeys[0].counter).toBe(0);
      expect(state.recvChains[1].messageKeys[0].counter).toBe(1);

      const helloAgain0Decrypted = await alice.decrypt(aliceStore, helloAgain0Encrypted);
      expect(sodium.to_string(helloAgain0Decrypted)).toBe(helloAgain0Plaintext);
    });

    it('replaces prekeys', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore1 = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));
      const bobStore2 = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore1.loadPrekey(0);
      expect(bobPrekey.keyId).toBe(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);

      const helloBob1Plaintext = 'Hello Bob!';
      const helloBob1Encrypted = await alice.encrypt(helloBob1Plaintext);

      const bob = await assertInitFromMessage(bobIdent, bobStore1, helloBob1Encrypted, helloBob1Plaintext);

      expect(Object.keys(bob.sessionStates).length).toBe(1);

      const helloBob2Plaintext = 'Hello Bob2!';
      const helloBob2Encrypted = await alice.encrypt(helloBob2Plaintext);

      const helloBob2Decrypted = await bob.decrypt(bobStore1, helloBob2Encrypted);
      expect(sodium.to_string(helloBob2Decrypted)).toBe(helloBob2Plaintext);

      expect(Object.keys(bob.sessionStates).length).toBe(1);

      const helloBob3Plaintext = 'Hello Bob3!';
      const helloBob3Encrypted = await alice.encrypt(helloBob3Plaintext);

      const helloBob3Decrypted = await bob.decrypt(bobStore2, helloBob3Encrypted);
      expect(sodium.to_string(helloBob3Decrypted)).toBe(helloBob3Plaintext);

      expect(Object.keys(bob.sessionStates).length).toBe(1);
    });
  });
  describe('Process', () => {
    it('works until the max counter gap', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();

      const preKeys = [await Proteus.keys.PreKey.lastResort()];
      const bobStore = new TestStore(preKeys);

      const bobPrekey = await bobStore.loadPrekey(Proteus.keys.PreKey.MAX_PREKEY_ID);
      expect(bobPrekey.keyId).toBe(Proteus.keys.PreKey.MAX_PREKEY_ID);

      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);

      const helloBob1Plaintext = 'Hello Bob1!';
      const helloBob1Encrypted = await alice.encrypt(helloBob1Plaintext);

      const bob = await assertInitFromMessage(bobIdent, bobStore, helloBob1Encrypted, helloBob1Plaintext);
      expect(Object.keys(bob.sessionStates).length).toBe(1);

      await Promise.all(
        Array.from({length: 1001}, async () => {
          const helloBob2Plaintext = 'Hello Bob2!';
          const helloBob2Encrypted = await alice.encrypt(helloBob2Plaintext);
          const helloBob2Decrypted = await bob.decrypt(bobStore, helloBob2Encrypted);
          expect(sodium.to_string(helloBob2Decrypted)).toBe(helloBob2Plaintext);
          expect(Object.keys(bob.sessionStates).length).toBe(1);
        }),
      );
    });

    it('pathological case', async () => {
      const numAlices = 32;
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();

      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, numAlices));
      const bobPrekeys = await bobStore.loadPrekeys();

      const alices = await Promise.all(
        bobPrekeys.map(pk => {
          const bundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, pk);
          return Proteus.session.Session.initFromPrekey(aliceIdent, bundle);
        }),
      );

      expect(alices.length).toBe(numAlices);

      const message = await alices[0].encrypt('Hello Bob!');
      const bob = await assertInitFromMessage(bobIdent, bobStore, message, 'Hello Bob!');

      await Promise.all(
        alices.map(async alice => {
          await Promise.all(Array.from({length: 900}, () => alice.encrypt('hello')));
          const encryptedMessage = await alice.encrypt('Hello Bob!');
          expect(sodium.to_string(await bob.decrypt(bobStore, encryptedMessage))).toBe('Hello Bob!');
        }),
      );

      expect(Object.keys(bob.sessionStates).length).toBe(numAlices);

      await Promise.all(
        alices.map(async alice => {
          const encryptedMessage = await alice.encrypt('Hello Bob!');
          expect(sodium.to_string(await bob.decrypt(bobStore, encryptedMessage))).toBe('Hello Bob!');
        }),
      );
    }, 10000);

    it('should handle mass communication', async () => {
      const aliceIdent = await Proteus.keys.IdentityKeyPair.new();
      const aliceStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobIdent = await Proteus.keys.IdentityKeyPair.new();
      const bobStore = new TestStore(await Proteus.keys.PreKey.generatePrekeys(0, 10));

      const bobPrekey = await bobStore.loadPrekey(0);
      const bobBundle = Proteus.keys.PreKeyBundle.new(bobIdent.publicKey, bobPrekey);

      const alice = await Proteus.session.Session.initFromPrekey(aliceIdent, bobBundle);
      const helloBob = await alice.encrypt('Hello Bob!');

      const bob = await assertInitFromMessage(bobIdent, bobStore, helloBob, 'Hello Bob!');

      // TODO: need to serialize/deserialize to/from CBOR here
      const messages = await Promise.all(Array.from({length: 999}, () => bob.encrypt('Hello Alice!')));

      await Promise.all(
        messages.map(async message => {
          const serialisedMessage = message.serialise();
          const deserialisedMessage = Proteus.message.Envelope.deserialise(serialisedMessage);
          const decryptedMessage = await alice.decrypt(aliceStore, deserialisedMessage);
          expect(sodium.to_string(decryptedMessage)).toBe('Hello Alice!');
        }),
      );

      assertSerialiseDeserialise(aliceIdent, alice);
      assertSerialiseDeserialise(bobIdent, bob);
    }, 10000);
  });
});
