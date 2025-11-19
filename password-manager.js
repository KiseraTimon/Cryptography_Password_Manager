"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
	/**
	 * Initializes the keychain using the provided information. Note that external
	 * users should likely never invoke the constructor directly and instead use
	 * either Keychain.init or Keychain.load. 
	 * Arguments:
	 *  You may design the constructor with any parameters you would like. 
	 * Return Type: void
	 */
	constructor() {
		this.data = {
			/* Store member variables that you intend to be public here
			   (i.e. information that will not compromise security if an adversary sees) */
		};
		this.secrets = {
			/* Store member variables that you intend to be private here
			   (information that an adversary should NOT see). */
		};

		throw "Not Implemented!";
	};

	/** 
	  * Creates an empty keychain with the given password.
	  *
	  * Arguments:
	  *   password: string
	  * Return Type: void
	  */
	static async init(password) {
		throw "Not Implemented!";
	}

	/**
	  * Loads the keychain state from the provided representation (repr). The
	  * repr variable will contain a JSON encoded serialization of the contents
	  * of the KVS (as returned by the dump function). The trustedDataCheck
	  * is an *optional* SHA-256 checksum that can be used to validate the 
	  * integrity of the contents of the KVS. If the checksum is provided and the
	  * integrity check fails, an exception should be thrown. You can assume that
	  * the representation passed to load is well-formed (i.e., it will be
	  * a valid JSON object).Returns a Keychain object that contains the data
	  * from repr. 
	  *
	  * Arguments:
	  *   password:           string
	  *   repr:               string
	  *   trustedDataCheck: string
	  * Return Type: Keychain
	  */
	static async load(password, repr, trustedDataCheck) {
		throw "Not Implemented!";
	};

	/**
	  * Returns a JSON serialization of the contents of the keychain that can be 
	  * loaded back using the load function. The return value should consist of
	  * an array of two strings:
	  *   arr[0] = JSON encoding of password manager
	  *   arr[1] = SHA-256 checksum (as a string)
	  * As discussed in the handout, the first element of the array should contain
	  * all of the data in the password manager. The second element is a SHA-256
	  * checksum computed over the password manager to preserve integrity.
	  *
	  * Return Type: array
	  */
	async dump() {
		throw "Not Implemented!";
	};


	/*
		* Fetches the data (as a string) corresponding to the given domain from the KVS.
		* If there is no entry in the KVS that matches the given domain, then return
		* null.
		*
		* Arguments:
		*   name: string
		* Return Type: Promise<string>
	*/
	async get(name) {
		const kvs = this.getKvs();
		const tagB64 = await this.domainToTag(name);
		const record = kvs[tagB64];
		if (!record) {
			return null;
		}
		const value = await this.decryptForDomain(name, record);
		return value;
	};


	/*
		 * Inserts the domain and associated data into the KVS. If the domain is
		 * already in the password manager, this method should update its value. If
		 * not, create a new entry in the password manager.
		 *
		 * Arguments:
		 *   name: string
		 *   value: string
		 * Return Type: void
	 */
	async set(name, value) {
		const kvs = this.getKvs();
		const { tagB64, record } = await this.encryptForDomain(name, value);
		kvs[tagB64] = record;
	};


	/*
		* Removes the record with name from the password manager. Returns true
		* if the record with the specified name is removed, false otherwise.
		*
		* Arguments:
		*   name: string
		* Return Type: Promise<boolean>
	*/
	async remove(name) {
		const kvs = this.getKvs();
		const tagB64 = await this.domainToTag(name);

		if (Object.prototype.hasOwnProperty.call(kvs, tagB64)) {
			delete kvs[tagB64];
			return true;
		}
		return false;
	};


	/*
	Internal Helper I:
	* Ensures the KVS object exists and is stored in a serializable location
	* It should map data
	*  from:
	*    Base64(HMAC(domain))
	*  to:
	*    { iv: <Base64>, ciphertext: <Base64> }
	*/
	getKvs() {
		if (!this.data.kvs) {
			this.data.kvs = {};
		}

		return this.data.kvs;
	}


	/*
	Internal Helper II:
	* Pads a password to a fixed length of 64 characters to avoid leaking password lengths
	* We will use null characters and strip them back off after decryption
	*/
	padPassword(value) {
		const maxLen = MAX_PASSWORD_LENGTH;

		if (value.length > maxLen) {
			throw new Error("Password has exceeded the max allowed")
		}

		return value.padEnd(maxLen, "\0");
	}


	/*
	Internal Helper III:
	* Removes null character padding on decrypted passwords
	*/
	unpadPassword(padded) {
		return padded.replace(/\0+$/g, "");
	}


	/*
	Internal Helper IV:
	* Compute HMAC(domain) and return it as a Base64 string.
	* This value is to be used both:
	*   - as the KVS key (to hide domain names)
	*   - as associatedData (AAD) in AES-GCM to prevent swap attacks.
	*/
	async domainToTag(name) {
		if (!this.secrets.hmacKey) {
			throw new Error("HMAC key not initialized");
		}

		const nameBuf = stringToBuffer(name);
		const macBuf = await subtle.sign(
			// The key already encodes algo/hash
			{ name: "HMAC" },
			this.secrets.hmacKey,
			nameBuf
		);

		// Base64-encoded HMAC
		return encodeBuffer(macBuf);
	}


	/*
	Internal Helper V:
	* Encrypt a value (password) for a given domain.
	* Pads the password to fixed length.
	* Computes HMAC(domain) and uses it as AAD in AES-GCM.
	* Returns { tagB64, record } where:
	*     tagB64 = Base64(HMAC(domain))
	*     record = { iv: <Base64>, ciphertext: <Base64> }
	*/
	async encryptForDomain(name, value) {
		if (!this.secrets.aesKey) {
			throw new Error("AES key not initialized");
		}

		// Deriving the domain tag = HMAC(domain), as Base64 string
		const tagB64 = await this.domainToTag(name);
		const tagBuf = decodeBuffer(tagB64);

		// Padding the password to hide its true length
		const padded = this.padPassword(value);
		const plaintextBuf = stringToBuffer(padded);

		// Generating a random IV (12 bytes = 96 bits)
		const ivBuf = getRandomBytes(12);

		// Encrypting with AES-GCM
		const ciphertextBuf = await subtle.encrypt(
			{
				name: "AES-GCM",
				iv: ivBuf,
				additionalData: tagBuf,
				tagLength: 128
			},
			this.secrets.aesKey,
			plaintextBuf
		);

		// Building the record with Base64 encoding (JSON-friendly)
		const record = {
			iv: encodeBuffer(ivBuf),
			ciphertext: encodeBuffer(ciphertextBuf)
		};

		return { tagB64, record };
	}


	/*
	Internal Helper VI:
	* Decrypts a record for a given domain.
	* Recomputes HMAC(domain) and uses it as AAD.
	* If a swap/tamper attack happened, AES-GCM auth will fail
	*/
	async decryptForDomain(name, record) {
		if (!this.secrets.aesKey) {
			throw new Error("AES key not initialized");
		}

		const tagB64 = await this.domainToTag(name);
		const tagBuf = decodeBuffer(tagB64);

		const ivBuf = decodeBuffer(record.iv);
		const ciphertextBuf = decodeBuffer(record.ciphertext);

		let plaintextBuf;
		try {
			plaintextBuf = await subtle.decrypt(
				{
					name: "AES-GCM",
					iv: ivBuf,
					additionalData: tagBuf,
					tagLength: 128
				},
				this.secrets.aesKey,
				ciphertextBuf
			);

		} catch (e) {
			// Indicating a swap attack or tampered ciphertext/IV
			throw new Error("Possible tampering detected (swap or modified record)");
		}

		const padded = bufferToString(plaintextBuf);
		return this.unpadPassword(padded);
	}
};

module.exports = { Keychain }
