# Pairing and setup sequence

These charts describe the Python/Linux companion in `probe/`.
They use the author's observations of Apple Watch SE 3 with watchOS 26.4 and
public specifications. Pairing, bonding, activation and initial sync were
demonstrated on that device. The Watch became usable on its own.

The charts group some acknowledgements and fragments. They are not packet
captures. Other Watch models and watchOS versions are untested.
Read [LEGAL.md](../LEGAL.md) before using or extending the implementation.

## Discovery, PIN authentication and bonding

```mermaid
sequenceDiagram
    actor U as Owner
    participant C as Python companion / Bumble
    participant W as Apple Watch

    C->>W: Active BLE scan
    W-->>C: Connectable advertisement + scan response (FE25, subtype 06)
    C->>C: Collect address/type, product and 12-byte setup data
    C-->>U: Select single Watch automatically#59; numbered choice if several
    C->>W: LE connection#59; Magnet CID 0x003a version/service negotiation
    W-->>C: Accept terminusPairing with directional L2CAP CIDs
    Note over C,W: Pairing traffic: IKE inside NRLP type 4, inside L2CAP ERTM

    rect rgb(238, 245, 255)
        Note over C,W: Control IKE session: encryption without authenticated peer identity
        C->>W: IKE_SA_INIT MID 0: proposals, X448 public key, Ni, SPIi
        W-->>C: Selected algorithms, X448 public key, Nr, SPIr
        Note over C,W: X448 shared secret#59; derive round-0 IKE keys with HMAC-SHA512 / prf+
        C->>W: Encrypted IKE_INTERMEDIATE MID 1: ML-KEM-1024 public key
        W-->>C: Encrypted ML-KEM-1024 ciphertext
        Note over C,W: Decapsulate / encapsulate shared secret#59; extend IKE keys#59; retain IntAuth
        C->>W: IKE_AUTH MID 2: NULL authentication (method 13)
        W-->>C: NULL AUTH response
        C->>W: Encrypted INFORMATIONAL: request PIN method (0xc545, method 2)
        W-->>C: PIN salt (0xc546), response or separate Watch request
        opt Watch initiated the salt message
            C->>W: Encrypted empty response after validating salt
        end
    end

    C-->>U: Ask for six-digit PIN displayed by this Watch
    U->>C: PIN, including leading zeros

    rect rgb(239, 250, 239)
        Note over C,W: Fresh PIN IKE session#59; separate nonces, SPIs and ephemeral keys
        C->>W: IKE_SA_INIT MID 0: X448, ML-KEM-1024, method 0x2af9, USE_PPK
        W-->>C: Accepted proposals, public key and nonce
        C->>W: Encrypted IKE_INTERMEDIATE MID 1: ML-KEM-1024 public key
        W-->>C: Encrypted ML-KEM ciphertext
        Note over C,W: Derive fresh hybrid IKE keys
        C->>C: Numeric PIN to uint32 big-endian#59; PBKDF2-SHA256 with Watch salt
        C->>C: 1,600,000 iterations, 32 bytes#59; append 12-byte setup data to form seed
        C->>C: Derive 64-byte PPK using HKDF-SHA512
        Note over C,W: Mix PPK into SK_d, SK_pi and SK_pr
        C->>C: HKDF-SHA256(seed, Ni || Nr), 80 bytes#59; reduce two 40-byte scalars
        Note over C,W: SPAKE2+ P-256: companion is Prover#59; Watch is Verifier
        C->>W: IKE_AUTH MID 2: IDs, GSPM share X, PPK identity 01
        W-->>C: IDs and GSPM share Y
        Note over C,W: Validate shares#59; compute SPAKE transcript, confirmation keys and shared key
        C->>W: IKE_AUTH MID 3: Prover confirmation tag
        W-->>C: Verifier confirmation tag
        C->>W: IKE_AUTH MID 4: method-12 AUTH bound to IKE transcript and ordered shares
        W-->>C: Method-12 AUTH and mandatory PPK identity
        C->>C: Verify peer AUTH#59; discard PIN and ephemeral SPAKE state
    end

    C->>C: Generate persistent UUID, Ed25519/X25519 identities and Bluetooth OOB data
    C->>W: Encrypted private notifications: identities, Class-D/C keys, OOB material
    W-->>C: Peer identity, Class-D/C keys, OOB material and metadata
    C->>C: Validate and persist peer material before acknowledging enrollment
    C->>W: Enrollment response when required#59; enable SMP pairing
    C->>W: Bluetooth LE Secure Connections OOB pairing
    W-->>C: Bond and encrypted link
    C->>C: Require authenticated SC / 128-bit key#59; persist LTK, peer identity and address
    Note over C,W: Close pairing relay#59; negotiate terminusLink for normal traffic
```

All encrypted IKE exchanges use AES-256-GCM with a 16-byte tag. SK/SKF carries
encrypted payloads; SKF handles fragmentation. HMAC-SHA512 is the IKE PRF.
NULL control authentication does not prove the Watch's identity; the PIN flow
must complete before trusting enrollment material or allowing SMP.

## Operational encryption, activation relay and initial sync

```mermaid
sequenceDiagram
    participant C as Python companion
    participant W as Apple Watch
    participant K as Linux TUN / TCP
    participant A as Apple activation server

    C->>W: Terminus prelude: role election and link state
    W-->>C: Peer prelude
    loop Class D, then Class C after peer-unlock indication
        C->>W: Fresh IKE_SA_INIT: X448 + ML-KEM-768
        W-->>C: Selected algorithms, public key and nonce
        C->>W: Encrypted IKE_INTERMEDIATE: ML-KEM-768 public key
        W-->>C: Encrypted KEM ciphertext
        Note over C,W: Derive fresh hybrid IKE keys
        C->>W: IKE_AUTH: HPKE-encrypted identifier, Ed25519 AUTH, ESP proposal, selectors/config
        W-->>C: Plain service KEY_ID, Ed25519 AUTH, selected ESP SA and IPv6 addresses
        Note over C,W: Use PIN-enrolled keys#59; verify identity, signature, prelude and negotiated profile
        Note over C,W: Derive directional AES-GCM implicit-IV ESP keys and salts
        opt Class D
            C->>W: Encrypted metadata and unlock notifications
            W-->>C: Receipts and peer-unlock indication (may arrive earlier)
        end
    end
    C->>K: Create TUN, assign D/C IPv6 addresses and peer routes
    C->>W: Encrypted LinkDirector announcements
    W-->>C: Encrypted receipts

    Note over C,K: Native TCP uses the host kernel#59; Python encrypts/decrypts ESP over NRLP/ERTM
    C->>K: Open IDS control and data connections
    K->>C: TCP IPv6 packets from TUN
    C->>W: ESP-protected NWSC signed service request and IDS Hello
    W-->>C: Protected peer feedback, Hello and data-lane setup
    C->>K: Authenticate/decrypt incoming ESP and deliver IPv6 packets
    C->>W: Mutual IDS device-info exchange (commands 11/12)
    W-->>C: Device-info response and receipts
    Note over C,W: IDS device info exchanges pairing identities#59; it does not sign into an Apple Account

    C->>W: NanoRegistry check, property snapshot and property request
    W-->>C: Receipts and Watch product/model/chip/capabilities
    C->>W: Configure and commit pairing#59; timezone/locale#59; start activation
    W-->>C: PBBridge activation request with archived URL, headers and body
    C->>A: HTTPS POST of Watch-generated request (verified TLS, HTTP/1.1)
    A-->>C: Activation response body and signature/header material
    C->>W: PBBridge response preserving signed application body bytes
    W-->>C: Activation and locale completion
    Note over C,A: The companion relays activation#59; it does not create Apple's signed record

    C->>W: Normal mode, PairedSync started, PrepareInitialSync
    W-->>C: Correlated prepare response
    C->>W: Preferences, PairedSync completion, progress and Buddy dismissal
    C->>W: Query current NanoRegistry isSetup
    W-->>C: Completion application receipt#59; Watch/client sync states#59; isSetup=true
    C->>C: Require activation + isSetup + completed sync states + matching application receipt
    Note over C,W: Protocol completion still requires a physical watch-face and built-in app check
```

## Limits

App sync is partial. The companion announces the default app list over the
app-sync conduit. The Watch uses its own Wi-Fi to download apps.
Automatic installation is untested.

Activation requests use the host's Internet connection.
The companion does not provide a general Internet relay for the Watch.
Software updates and Apple Account sign-in are not implemented.
An Activation Lock ownership challenge is not successful activation.
