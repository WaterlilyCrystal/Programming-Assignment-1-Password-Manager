"use strict";

/********* External Imports ********/
const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/
const PBKDF2_ITERATIONS = 100000;
const MAX_PASSWORD_LENGTH = 64;
const AES_KEY_LENGTH = 256;
const HMAC_KEY_LENGTH = 256;
const IV_LENGTH = 12;

class Keychain {
    constructor() {
        this.data = {};
        this.secrets = { masterKey: null, masterSalt: null };
    }

    static async init(password) {
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new Error(`Password exceeds maximum length of ${MAX_PASSWORD_LENGTH}`);
        }
        
        const keychain = new Keychain();
        keychain.secrets.masterSalt = getRandomBytes(16);
        keychain.secrets.masterKey = await Keychain.deriveKey(password, keychain.secrets.masterSalt);
        return keychain;
    }

    static async load(password, repr, trustedDataCheck) {
        if (password.length > MAX_PASSWORD_LENGTH) {
            throw new Error(`Password exceeds maximum length of ${MAX_PASSWORD_LENGTH}`);
        }

        const [encryptedData, salt, checksum] = JSON.parse(repr);
        if (trustedDataCheck && checksum !== trustedDataCheck) {
            throw new Error("Integrity check failed");
        }

        const keychain = new Keychain();
        keychain.secrets.masterSalt = decodeBuffer(salt);
        keychain.secrets.masterKey = await Keychain.deriveKey(password, keychain.secrets.masterSalt);
        
        const computedChecksum = await Keychain.computeChecksum(encryptedData);
        if (computedChecksum !== checksum) {
            throw new Error("Integrity verification failed");
        }

        keychain.data = JSON.parse(await Keychain.decryptData(encryptedData, keychain.secrets.masterKey));
        return keychain;
    }

    async dump() {
        if (!this.secrets.masterKey) {
            throw new Error("Master key not initialized");
        }

        const dataString = JSON.stringify(this.data);
        const encryptedData = await Keychain.encryptData(dataString, this.secrets.masterKey);
        const checksum = await Keychain.computeChecksum(encryptedData);
        
        return [encryptedData, encodeBuffer(this.secrets.masterSalt), checksum];
    }

    async set(name, value) {
        if (!this.secrets.masterKey) throw new Error("Master key not initialized");
        
        const hmacKey = await Keychain.deriveHMACKey(this.secrets.masterKey);
        const hmac = await Keychain.computeHMAC(hmacKey, stringToBuffer(name));
        
        const paddedPassword = Keychain.padPKCS7(stringToBuffer(value));
        const encryptedPassword = await Keychain.encryptData(paddedPassword, this.secrets.masterKey);
        
        this.data[encodeBuffer(hmac)] = encryptedPassword;
    }

    async get(name) {
        if (!this.secrets.masterKey) throw new Error("Master key not initialized");
        
        const hmacKey = await Keychain.deriveHMACKey(this.secrets.masterKey);
        const hmac = await Keychain.computeHMAC(hmacKey, stringToBuffer(name));
        
        const encryptedPassword = this.data[encodeBuffer(hmac)];
        if (!encryptedPassword) return null;
        
        const decryptedPassword = await Keychain.decryptData(encryptedPassword, this.secrets.masterKey);
        return bufferToString(Keychain.unpadPKCS7(stringToBuffer(decryptedPassword)));
    }

    async remove(name) {
        const hmacKey = await Keychain.deriveHMACKey(this.secrets.masterKey);
        const hmac = await Keychain.computeHMAC(hmacKey, stringToBuffer(name));
        return delete this.data[encodeBuffer(hmac)];
    }

    static async deriveKey(password, salt) {
        const keyMaterial = await subtle.importKey("raw", stringToBuffer(password), { name: "PBKDF2" }, false, ["deriveKey"]);
        return await subtle.deriveKey({ name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, keyMaterial, { name: "AES-GCM", length: AES_KEY_LENGTH }, true, ["encrypt", "decrypt"]);
    }

    static async deriveHMACKey(masterKey) {
        return await subtle.deriveKey({ name: "PBKDF2", salt: stringToBuffer("hmac-salt"), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" }, masterKey, { name: "HMAC", hash: "SHA-256", length: HMAC_KEY_LENGTH }, true, ["sign"]);
    }

    static async encryptData(data, key) {
        const iv = getRandomBytes(IV_LENGTH);
        const encrypted = await subtle.encrypt({ name: "AES-GCM", iv }, key, data);
        return encodeBuffer(new Uint8Array([...iv, ...new Uint8Array(encrypted)]));
    }

    static async decryptData(encryptedData, key) {
        const combinedBuffer = decodeBuffer(encryptedData);
        const iv = combinedBuffer.slice(0, IV_LENGTH);
        const ciphertext = combinedBuffer.slice(IV_LENGTH);
        const decrypted = await subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
        return bufferToString(new Uint8Array(decrypted));
    }

    static async computeHMAC(key, data) {
        const signature = await subtle.sign("HMAC", key, data);
        return new Uint8Array(signature);
    }

    static async computeChecksum(data) {
        const hashBuffer = await subtle.digest("SHA-256", stringToBuffer(data));
        return encodeBuffer(new Uint8Array(hashBuffer));
    }

    static padPKCS7(data) {
        const padding = 64 - (data.length % 64);
        const padded = new Uint8Array(data.length + padding);
        padded.set(data);
        padded.fill(padding, data.length);
        return padded;
    }

    static unpadPKCS7(data) {
        return data.slice(0, data.length - data[data.length - 1]);
    }
}

module.exports = { Keychain };
