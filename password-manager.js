"use strict";

const crypto = require('crypto');

// Constants
const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;
const AES_KEY_LENGTH = 256; // in bits
const SALT_LENGTH = 16; // in bytes
const HMAC_KEY_LENGTH = 32; // in bytes
const IV_LENGTH = 12; // in bytes for AES-GCM
const AES_BLOCK_SIZE = 16; // in bytes

class Keychain {
    constructor() {
        this.data = {
            kvs: {}, // Key-Value Store
        };
        this.secrets = {
            masterKey: null, // Master key derived from master password
            hmacKey: null,   // HMAC key for domain names
            salt: null,      // Salt used for key derivation
        };
    }

    // Helper function to convert string to buffer
    static stringToBuffer(str) {
        return Buffer.from(str, 'utf8');
    }

    // Helper function to convert buffer to string
    static bufferToString(buf) {
        return buf.toString('utf8');
    }

    // Helper function to encode buffer to base64
    static encodeBuffer(buf) {
        return buf.toString('base64');
    }

    // Helper function to decode base64 to buffer
    static decodeBuffer(str) {
        return Buffer.from(str, 'base64');
    }

    // Generate a key using PBKDF2
    static generateKey(password, salt, iterations, keyLength) {
        return crypto.pbkdf2Sync(password, salt, iterations, keyLength / 8, 'sha256');
    }

    // Generate a random salt
    static generateSalt(length) {
        return crypto.randomBytes(length);
    }

    // Generate a random IV
    static generateIV(length) {
        return crypto.randomBytes(length);
    }

    // Add PKCS7 padding
    static addPKCS7Padding(data) {
        const paddingLength = AES_BLOCK_SIZE - (data.length % AES_BLOCK_SIZE);
        const padding = Buffer.alloc(paddingLength, paddingLength);
        return Buffer.concat([data, padding]);
    }

    // Remove PKCS7 padding
    static removePKCS7Padding(data) {
        const paddingLength = data[data.length - 1];
        return data.slice(0, data.length - paddingLength);
    }

    // Encrypt data using AES-GCM with PKCS7 padding
    static encryptAESGCM(key, iv, plaintext) {
        const paddedPlaintext = Keychain.addPKCS7Padding(Keychain.stringToBuffer(plaintext));
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([cipher.update(paddedPlaintext), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { encrypted, tag };
    }

    // Decrypt data using AES-GCM and remove PKCS7 padding
    static decryptAESGCM(key, iv, encrypted, tag) {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(tag);
        const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
        return Keychain.bufferToString(Keychain.removePKCS7Padding(decrypted));
    }

    // Hash domain name using HMAC
    static hashHMAC(key, domain) {
        const hmac = crypto.createHmac('sha256', key);
        hmac.update(domain);
        return hmac.digest('hex');
    }

    // Initialize a new keychain with a password (matches test's init method)
    static async init(keychainPassword) {
        const keychain = new Keychain();
        const salt = Keychain.generateSalt(SALT_LENGTH);
        const masterKey = Keychain.generateKey(keychainPassword, salt, PBKDF2_ITERATIONS, AES_KEY_LENGTH);
        const hmacKey = Keychain.generateKey(keychainPassword, salt, PBKDF2_ITERATIONS, HMAC_KEY_LENGTH);

        keychain.secrets.masterKey = masterKey;
        keychain.secrets.hmacKey = hmacKey;
        keychain.secrets.salt = salt;

        return keychain;
    }

    // Load a keychain from a serialized representation
    static async load(keychainPassword, repr, trustedDataCheck) {
        try {
            const keychain = new Keychain();
            const data = JSON.parse(repr);

            // Verify checksum
            const checksum = crypto.createHash('sha256').update(repr).digest('base64');
            
            if (checksum !== trustedDataCheck) {
                throw new Error('Checksum verification failed');
            }

            const salt = Keychain.decodeBuffer(data.salt);
            const masterKey = Keychain.generateKey(keychainPassword, salt, PBKDF2_ITERATIONS, AES_KEY_LENGTH);
            
            // Test decryption of a value to verify the password
            const kvs = data.kvs;
            const testEntryKey = Object.keys(kvs)[0];
            
            if (testEntryKey) {
                const testEntry = kvs[testEntryKey];
                try {
                    Keychain.decryptAESGCM(
                        masterKey, 
                        Keychain.decodeBuffer(testEntry.iv), 
                        Keychain.decodeBuffer(testEntry.encrypted), 
                        Keychain.decodeBuffer(testEntry.tag)
                    );
                } catch (e) {
                    throw new Error('Invalid password');
                }
            }

            keychain.secrets.masterKey = masterKey;
            keychain.secrets.hmacKey = Keychain.decodeBuffer(data.hmacKey);
            keychain.secrets.salt = salt;
            keychain.data.kvs = kvs;

            return keychain;
        } catch (e) {
            return Promise.reject(e);
        }
    }

    // Dump the keychain to a serialized representation
    async dump() {
        const repr = JSON.stringify({
            kvs: this.data.kvs,
            salt: Keychain.encodeBuffer(this.secrets.salt),
            hmacKey: Keychain.encodeBuffer(this.secrets.hmacKey),
        });
        const checksum = crypto.createHash('sha256').update(repr).digest('base64');
        return [repr, checksum];
    }

    // Get a password for a domain
    async get(domain) {
        const hashedDomain = Keychain.hashHMAC(this.secrets.hmacKey, domain);
        const encryptedData = this.data.kvs[hashedDomain];

        if (!encryptedData) {
            return null;
        }

        const { iv, encrypted, tag } = encryptedData;
        return Keychain.decryptAESGCM(
            this.secrets.masterKey, 
            Keychain.decodeBuffer(iv), 
            Keychain.decodeBuffer(encrypted), 
            Keychain.decodeBuffer(tag)
        );
    }

    // Set a password for a domain
    async set(domain, password) {
        const hashedDomain = Keychain.hashHMAC(this.secrets.hmacKey, domain);
        const iv = Keychain.generateIV(IV_LENGTH);
        const { encrypted, tag } = Keychain.encryptAESGCM(this.secrets.masterKey, iv, password);

        this.data.kvs[hashedDomain] = {
            iv: Keychain.encodeBuffer(iv),
            encrypted: Keychain.encodeBuffer(encrypted),
            tag: Keychain.encodeBuffer(tag),
        };
    }

    // Remove a domain from the keychain
    async remove(domain) {
        const hashedDomain = Keychain.hashHMAC(this.secrets.hmacKey, domain);
        if (this.data.kvs[hashedDomain]) {
            delete this.data.kvs[hashedDomain];
            return true;
        }
        return false;
    }
}

module.exports = { Keychain }
