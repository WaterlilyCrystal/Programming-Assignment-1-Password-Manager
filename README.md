# Password Manager Security Report

## Group information
- Group 8
- Members:
   - Phan Thu Ha 
   - Nguyen Phuong Linh 
   - Pham Nguyen Hai Nhi 

## 1. Briefly describe your method for preventing the adversary from learning information about the lengths of the passwords stored in your password manager.
To prevent an adversary from learning information about the lengths of passwords stored in the password manager, I implemented PKCS#7 padding to all passwords before encryption. This ensures that every password is padded to a fixed block size (16 bytes/AES block size in my implementation) before encryption. By padding all passwords, the ciphertext length becomes a function of the block size rather than the original password length, thus hiding the true length of the password from attackers who might analyze the encrypted data.

## 2. Briefly describe your method for preventing swap attacks (Section 2.2). Provide an argument for why the attack is prevented in your scheme.
To prevent swap attacks, I implemented domain binding using HMAC. Specifically:
- When storing a password, I compute HMAC(domain, hmacKey) to create a unique identifier for each domain.
- The password is stored in the key-value store using this HMAC value as the key.
- When retrieving a password, the system recomputes the HMAC for the requested domain and uses it to look up the password.

This prevents swap attacks because even if an adversary moves encrypted password entries between domains, when a user requests a password for domain A, the system will compute HMAC(A, hmacKey) and look up that specific entry. The attacker cannot forge this HMAC without knowing the secret hmacKey, so they cannot make domain A point to domain B's password. Each password is cryptographically bound to its domain through the HMAC.

## 3. In our proposed defense against the rollback attack (Section 2.2), we assume that we can store the SHA-256 hash in a trusted location beyond the reach of an adversary. Is it necessary to assume that such a trusted location exists, in order to defend against rollback attacks? Briefly justify your answer.
Yes, it is necessary to assume that a trusted location exists in order to effectively defend against rollback attacks.

A rollback attack occurs when an adversary replaces a newer, updated database state with an older version, effectively undoing security changes. Without a trusted location to store integrity verification data, this attack cannot be reliably prevented because:

- If we store the integrity check (SHA-256 hash) alongside the database itself, an adversary who can modify the database can simply replace both the database and its hash with older versions.
- The password manager would have no way to distinguish between a legitimate state and a rolled-back state since both the data and its integrity check would be consistent with each other.
- The trusted location serves as an anchor of trust that the adversary cannot tamper with, allowing the password manager to detect when the database has been rolled back.

Therefore, a trusted location outside the adversary's reach is essential for any effective defense against rollback attacks.

## 4. Because HMAC is a deterministic MAC (that is, its output is the same if it is run multiple times with the same input), we were able to look up domain names using their HMAC values. There are also randomized MACs, which can output different tags on multiple runs with the same input. Explain how you would do the look up if you had to use a randomized MAC instead of HMAC. Is there a performance penalty involved, and if so, what?
If using a randomized MAC instead of HMAC, we would need to:

1. Store both the domain name (encrypted) and its randomized MAC in each record
2. To look up a password, we would:
   - Compute a new MAC for the queried domain
   - Decrypt all stored domain names and compare them with the queried domain
   - Return the password associated with the matching domain

This approach incurs significant performance penalties compared to using HMAC:
- Time complexity increases from O(1) to O(n) where n is the number of stored passwords
- We must perform decryption operations on every domain name in the database
- Additional storage is required as we need to store both the encrypted domain and its MAC
- More cryptographic operations are performed per lookup, increasing computational cost

The deterministic nature of HMAC allows for efficient direct lookups using hash tables, while randomized MACs sacrifice this efficiency for their added security properties.

## 5. In our specification, we leak the number of records in the password manager. Describe an approach to reduce the information leaked about the number of records. Specifically, if there are k records, your scheme should only leak ⌊log2(k)⌋ (that is, if k1 and k2 are such that ⌊log2(k1)⌋ = ⌊log2(k2)⌋, the attacker should not be able to distinguish between a case where the true number of records is k1 and another case where the true number of records is k2).
To reduce information leaked about the number of records, we can implement a padding scheme based on powers of 2:

1. Calculate n = 2^⌈log2(k)⌉ (the next power of 2 greater than or equal to k)
2. Add (n - k) dummy records with random domain hashes and encrypted random data
3. When looking up passwords, ignore these dummy records

This approach ensures:
- The total number of records is always a power of 2
- If k1 and k2 have the same ⌊log2(k)⌋, they will be padded to the same total number of records
- An attacker only learns which power of 2 range the true record count falls into
- The implementation is straightforward and maintains the efficiency of lookups

The dummy records should be indistinguishable from real records to prevent statistical analysis attacks, using random values for all fields that would appear in legitimate records.

## 6. What is a way we can add multi-user support for specific sites to our password manager system without compromising security for other sites that these users may wish to store passwords of? That is, if Alice and Bob wish to access one stored password (say for nytimes) that either of them can get and update, without allowing the other to access their passwords for other websites.
To implement secure multi-user support for specific sites:

1. Generate a unique symmetric key (sharing key) for each shared site (e.g., NYTimes)
2. Encrypt the site password using this sharing key
3. Encrypt copies of the sharing key separately with each authorized user's master key
4. Store these encrypted sharing keys in each user's keychain entry for the shared site

For example, with Alice and Bob sharing a NYTimes password:
- Generate key K_nytimes
- Encrypt NYTimes password with K_nytimes
- Encrypt K_nytimes with Alice's master key → Store in Alice's keychain
- Encrypt K_nytimes with Bob's master key → Store in Bob's keychain

When Alice or Bob wants to access the NYTimes password:
1. They decrypt their copy of K_nytimes using their master key
2. They use K_nytimes to decrypt the shared NYTimes password

This approach ensures:
- Only authorized users can access the shared password
- Personal passwords remain private, as they're still encrypted with individual master keys
- The system scales efficiently to multiple users per shared site
- Updates to shared passwords are immediately available to all authorized users
