---
title: "Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE"
abbrev: "PQ HPKE"
category: std

docname: draft-ietf-hpke-pq-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: SEC
workgroup: "HPKE Publication, Kept Efficient"
keyword:
 - hybrid public key encryption
 - hpke
 - post-quantum
venue:
  group: "HPKE Publication, Kept Efficient"
  type: ""
  mail: "hpke@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/hpke"
  github: "hpkewg/hpke-pq"
  latest: "https://hpkewg.github.io/hpke-pq/draft-barnes-hpke-pq.html"

author:
 -
    fullname: "Richard Barnes"
    organization: Cisco
    email: "rlb@ipv.sx"

normative:
  FIPS186: DOI.10.6028/NIST.FIPS.186-5
  FIPS202: DOI.10.6028/NIST.FIPS.202
  FIPS203: DOI.10.6028/NIST.FIPS.203
  CONCRETE:
    title: "TODO - CFRG Concrete hybrid KEMs"
    date: Jun, 2001

informative:
  CDM23:
    title: "Keeping Up with the KEMs: Stronger Security Notions for KEMs and automated analysis of KEM-based protocols"
    target: https://eprint.iacr.org/2023/1933.pdf
    date: 2023
    author:
      -
        ins: C. Cremers
        name: Cas Cremers
        org: CISPA Helmholtz Center for Information Security
      -
        ins: A. Dax
        name: Alexander Dax
        org: CISPA Helmholtz Center for Information Security
      -
        ins: N. Medinger
        name: Niklas Medinger
        org: CISPA Helmholtz Center for Information Security
  TestVectors:
    title: "HPKE Test Vectors for Post-Quantum Algorithms"
    target: https://github.com/hpkewg/hpke-pq/blob/main/test-vectors.json
    date: 2025

--- abstract

Updating key exchange and public-key encryption protocols to resist attack by
quantum computers is a high priority given the possibility of "harvest now,
decrypt later" attacks.  Hybrid Public Key Encryption (HPKE) is a widely-used
public key encryption scheme based on combining a Key Encapsulation Mechanism
(KEM), a Key Derivation Function (KDF), and an Authenticated Encryption with
Associated Data (AEAD) scheme.  In this document, we define KEM algorithms for
HPKE based on both post-quantum KEMs and hybrid constructions of post-quantum
KEMs with traditional KEMs, as well as a KDF based on SHA-3 that is suitable for
use with these KEMs.  When used with these algorithms, HPKE is resilient with
respect to attacks by a quantum computer.

--- middle

# Introduction

A cryptographically relevant quantum computer may or may not exist as of this
writing.  The conventional wisdom, however, is that if one does not already,
then it likely will within the lifetime of information that is cryptographically
protected today.  Such a computer would have the ability to infer decapsulation
keys from encapsulation keys used for traditional KEMs, e.g., KEMs based on
Diffie-Hellman over finite fields or elliptic curves.  And it would be able to
do this not just for data encrypted after the creation of the computer, but also
for any information observed by the attacker previously, and stored for later
decryption.  This is the so-called "harvest now, decrypt later" attack.

It is thus a high priority for many organizations right now to migrate key
exchange technologies to use "post-quantum" (PQ) algorithms, which are resistant
to attack by a quantum computer {{?I-D.ietf-pquip-pqc-engineers}}.  Since these PQ
algorithms are relatively new, there is also interest in hybrid constructions
combining PQ algorithms with traditional KEMs, so that if the PQ algorithm
fails, then the traditional algorithm will still provide security, at least
against classical attacks.

Hybrid Public Key Encryption (HPKE) is a widely-used public key encryption
scheme based on combining a Key Encapsulation Mechanism (KEM), a Key Derivation
Function (KDF), and an Authenticated Encryption with Associated Data (AEAD)
scheme {{!I-D.barnes-hpke-hpke}}.  It is the foundation of the Messaging Layer
Security (MLS) protocol, the Oblivious HTTP protocol, and the TLS Encrypted
ClientHello extension {{?RFC9420}} {{?RFC9458}} {{?I-D.ietf-tls-esni}}.

This document defines a collection of PQ and PQ/T KEM algorithms for HPKE, which
allows HPKE to provide post-quantum security, as discussed in
{{security-considerations}}:

* ML-KEM-512
* ML-KEM-768
* ML-KEM-1024
* X25519 + ML-KEM-768
* P-256 + ML-KEM-768
* P-384 + ML-KEM-1024

ML-KEM, X25519, and P-256/P-384 are defined in {{FIPS203}}, {{!RFC7748}}, and
{{FIPS186}}, respectively.

This selection of KEM algorithms was chosen to provide a reasonably consolidated
set of algorithms (in the interest of broad interoperability), while still
allowing HPKE users flexibility along a few axes:

* Pure PQ vs. PQ/T hybrid
* CFRG-defined vs. NIST-defined elliptic curves
* Different security levels (NIST category 3 vs. category 5)

We also define HPKE KDF algorithms based on the SHA-3 family of hash functions.
SHA-3 is used internally to ML-KEM, and so it could be convenient for HPKE users
using the KEM algorithms in this document to rely solely on SHA-3.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

We generally use the terminology defined in the HPKE specification
{{I-D.barnes-hpke-hpke}}.

There are two meanings of "hybrid" in this document.  In the context of "hybrid
public key encryption", it refers to the combination of an asymmetric KEM
operaiton and a symmetric AEAD operation.  In the context of "PQ/T hybrid",
refers to the combination of PQ and traditional KEMs.  For clarity, we always
use "HPKE" for the former, and "PQ/T hybrid" for the latter.

# ML-KEM

The NIST Module-Lattice-Based Key-Encapsulation Mechanism is defined in
{{FIPS203}}.  In this section, we define how to implement the HPKE KEM interface
using ML-KEM.

The HPKE `DeriveKeyPair` function corresponds to the function
`ML-KEM.KeyGen_internal` in {{FIPS203}}.  The input `ikm` MUST be exactly
`Nsk = 64` bytes long.  The `d` and `z` inputs to `ML-KEM.KeyGen_internal` are
the first and last 32-byte segments of `ikm`, respectively.  The output `skX` is
the generated decapsulation key and the output `pkX` is the generated
encapsulation key.

~~~ pseudocode
def DeriveKeyPair(ikm):
    if len(ikm) != 64:
        raise DeriveKeyPairError

    d = ikm[:32]
    z = ikm[32:]

    dk = ikm
    (ek, _) = ML-KEM.KeyGen_internal(d, z)
    return (dk, ek)
~~~

The `GenerateKeyPair` function is simply `DeriveKeyPair` with a pseudorandom
`ikm` value.  As long as the bytes supplied by `random` meet the randomness
requirements of {{FIPS203}}, this corresponds to the `ML-KEM.KeyGen` function,
with the distinction that the decapsulation key is returned in seed format
rather than the expanded form returned by `ML-KEM.KeyGen`.

~~~ pseudocode
def GenerateKeyPair():
    dz = random(64)
    return DeriveKeyPair(dz)
~~~

The `SerializePublicKey` and `DeserializePublicKey` functions are both the
identity function, since the ML-KEM already uses fixed-length byte strings for
public encapsulation keys.  The length of the byte string is determined by the
ML-KEM parameter set in use.

The `Encap` function corresponds to the function `ML-KEM.Encaps` in
{{FIPS203}}, where an ML-KEM encapsulation key check failure causes an HPKE
`EncapError`.

The `Decap` function corresponds to the function `ML-KEM.Decaps` in
{{FIPS203}}, where any of an ML-KEM ciphertext check failure, decapsulation key check failure,
or hash check failure causes an HPKE `DecapError`. To be explicit, we derive the
expanded decapsulation key from the 64-byte seed format and invoke
`ML-KEM.Decaps` with it:

~~~ pseudocode
def Decap(enc, skR):
    d = skR[:32]
    z = skR[32:]
    (_, dk) = ML-KEM.KeyGen_internal(d, z)
    return ML-KEM.Decaps(dk, enc)
~~~

The constants `Nsecret` and `Nsk` are always 32 and 64, respectively.  The
constants `Nenc` and `Npk` depend on the ML-KEM parameter set in use; they are
specified in {{ml-kem-iana-table}}.

{:aside}
> Note: While this document defines an HPKE KEM for ML-KEM-512 in the interest
> of completeness, implementors should generally prefer ML-KEM-768 or
> ML-KEM-1024, or the PQ/T hybrids described in {{hybrids}}.  According to
> current cryptanalysis, ML-KEM-512 provides security compatible with a 128-bit
> security level (or NIST security category 1).  Given the relative novelty of
> ML-KEM, however, there is some concern that new cryptanalysis might reduce the
> security level of ML-KEM-512.  Use of ML-KEM-768 or ML-KEM-1024 acts as a
> hedge against cryptanalysis of ML-KEM that removes some bits of security but
> is not catastrophic, at a modest performance penalty.

# Hybrid KEMs with ECDH and ML-KEM {#hybrids}

{{CONCRETE}} defines a collection of concrete PQ/T hybrid KEMs.  These KEMs
combine a traditional ECDH group with ML-KEM:

QSF-P256-MLKEM768-SHAKE256-SHA3256:
: P-256 + ML-KEM-768

QSF-X25519-MLKEM768-SHAKE256-SHA3256:
: X25519 + ML-KEM-768

QSF-P384-MLKEM1024-SHAKE256-SHA3256:
: P-384 + ML-KEM-1024
{: spacing="compact"}

These KEMs satisfy the KEM interface defined in {{!I-D.irtf-cfrg-hybrid-kems}}.
This interface is mostly the same as the KEM interface in {{Section 4 of
!I-D.ietf-hpke-hpke}}, with the following mapping:

* The `GenerateKeyPair`, `DeriveKeyPair`, and `Encap` and `Decap` algorithms
  are identical.

* The `SerializePublicKey` and `DeserializePublicKey` algorithms are the
  identity, since encapsulation keys are already fixed-length byte strings.

* The constants map as follows:
    * `Nsecret = Nss`
    * `Nenc = Nct`
    * `Npk = Nek`
    * `Nsk = Ndk`

# Single-Stage KDFs

This section defines HPKE KDFs for three eXtendable Output Functions (XOF) based
on Keccak.  SHAKE is defined as part of the SHA-3 specification {{FIPS202}}, and
the related TurboSHAKE XOFs is defined in {{!I-D.irtf-cfrg-kangarootwelve}}.

The `Derive()` function for SHAKE is as follows,
where `<SIZE>` is either 128 or 256:

~~~ pseudocode
def SHAKE<SIZE>.Derive(ikm, L):
    return SHAKE<SIZE>(M = ikm, d = 8*L)
~~~

The `Derive()` function for TurboSHAKE is as follows,
where `<SIZE>` is either 128 or 256:

~~~ pseudocode
def TurboSHAKE<SIZE>.Derive(ikm, L):
    return TurboSHAKE<SIZE>(M = ikm, D = 0x1f, L)
~~~

The `Nh` values for the KDFs defined in this section are listed in
{{kdfid-values}}.

| Value  | KDF           | Nh  | Two-Stage | Reference |
|:-------|:--------------|-----|-----------|:----------|
| 0x0010 | SHAKE128      | 32  | N         | RFC XXXX  |
| 0x0011 | SHAKE256      | 64  | N         | RFC XXXX  |
| 0x0012 | TurboSHAKE128 | 32  | N         | RFC XXXX  |
| 0x0013 | TurboSHAKE256 | 64  | N         | RFC XXXX  |
{: #kdfid-values title="Single-Stage KDF IDs"}

[[ RFC EDITOR: Please change "XXXX" above to the RFC number assigned to this
document. ]]

# Selection of AEAD algorithms

As discussed in {{Section 2.1 of I-D.ietf-pquip-pqc-engineers}}, the advent of
quantum computers does not necessarily require changes in the AEAD algorithms
used in HPKE.  However, some compliance regimes call for the use of AEAD
algorithms with longer key lengths, for example, the AES-256-GCM or
ChaCha20Poly1305 algorithms registered for HPKE instead of AES-128-GCM.

# Security Considerations

As discussed in the HPKE Security Considerations, HPKE is an IND-CCA2 secure
public-key encryption scheme if the KEM it uses is IND-CCA secure.  It follows
that HPKE is IND-CCA2 secure against a quantum attacker if it uses a KEM that
provides IND-CCA security against a quantum attacker, i.e., a PQ KEM.  The KEM
algorithms defined in this document provide this level of security.  ML-KEM
itself is IND-CCA secure, and the IND-CCA security of the hybrid constructions
used in this document is established in {{!I-D.irtf-cfrg-hybrid-kems}}.

Another security property that is salient in some use cases is "key binding".
In {{CDM23}}, these notions are referred to with the shorthand X-BIND-P-Q.
The most salient for protocol design provide assurances similar to those
provided by transcript hashing in protocols like TLS:

LEAK-BIND-K-PK:
: If the sender and receiver have the same key (`K`, `shared_secret` above),
then there is only one encapsulation key (`PK`, `pk`) that could have produced
it, even if the decapsulation key is leaked to an attacker after the encryption
has been done.

LEAK-BIND-K-CT:
: If the sender and receiver have the same key (`K`, `shared_secret` above),
then there is only one KEM ciphertext (`CT`, `enc`) that could have produced
it, even if the decapsulation key is leaked to an attacker after the encryption
has been done.

DHKEM and ML-KEM meet these properties, as shown in {{CDM23}}.  QSF-based hybrid
KEMs also provide these properties, as discussed in
{{I-D.irtf-cfrg-hybrid-kems}}.

## PQ Hybrid vs. Pure PQ

Assuming that ML-KEM is secure, either the PQ/T hybrid KEMs defined in
{{hybrids}} or the pure PQ KEMs defined in {{ml-kem}} provide security against a
quantum attacker.  Hybrid KEMs can be used to provide security against a
non-quantum attacker in the event of failures with regard to the PQ algorithm,
including both implementation flaws as well as new cryptanalysis. See
{{?I-D.irtf-cfrg-hybrid-kems}} for further analysis of hybrid security
properties.

## Asymmetric-key-authenticated modes of RFC9180

In the {{?RFC9180}} version of HPKE, KEMs could optionally define the
additional functions `AuthEncap` and `AuthDecap`. These functions allowed
a sender to authenticate the message to the recipient without interaction.

The KEMs defined in this document do not support `AuthEncap`/`AuthDecap` and
cannot be used to migrate uses of HPKE that rely on this mode.
PSK-authenticated HPKE ({{Section 5.1.2 of I-D.barnes-hpke-hpke}})
or digital signatures may be suitable alternatives.

# IANA Considerations

This section requests that IANA perform three actions:

1. Update the entries in HPKE KEM Identifiers registry corresponding to ML-KEM
   algorithms.
2. Add entries to the HPKE KEM Identifiers registry for the PQ/T hybrid KEMs
   defined in this document.
3. Add entries to the HPKE KDF Identifiers registry for the SHA-3 KDFs defined
   in this document.

## Updated ML-KEM KEM Entries

IANA is requested to replace the entries in the HPKE KEM Identifiers registry
for values `0x0040`, `0x0041`, and `0x0042` with the following values:

| Value  | KEM         | Nsecret  | Nenc | Npk  | Nsk | Auth | Reference |
|:-------|:------------|:---------|:-----|:-----|:----|:-----|:----------|
| 0x0040 | ML-KEM-512  | 32       | 768  | 800  | 64  | no   | RFCXXXX   |
| 0x0041 | ML-KEM-768  | 32       | 1088 | 1184 | 64  | no   | RFCXXXX   |
| 0x0042 | ML-KEM-1024 | 32       | 1568 | 1568 | 64  | no   | RFCXXXX   |
{: #ml-kem-iana-table title="Updated ML-KEM entries for the HPKE KEM Identifiers table" }

The only change being made is to update the "Reference" column to refer to this
document.

## PQ/T Hybrid KEM Entries

IANA is requested to add the following entries to the HPKE KEM Identifiers registry:

| Value  | KEM                                  | Nsecret  | Nenc | Npk  | Nsk | Auth | Reference |
|:-------|:-------------------------------------|:---------|:-----|:-----|:----|:-----|:----------|
| 0x0050 | QSF-P256-MLKEM768-SHAKE256-SHA3256   | 32       | 1153 | 1249 | 32  | no   | RFCXXXX   |
| 0x0051 | QSF-X25519-MLKEM768-SHAKE256-SHA3256 | 32       | 1221 | 1317 | 32  | no   | RFCXXXX   |
| 0x0052 | QSF-P384-MLKEM1024-SHAKE256-SHA3256  | 32       | 1120 | 1600 | 32  | no   | RFCXXXX   |
{: #pqt-iana-table title="New PQ/T for the HPKE KEM Identifiers table" }


## SHA-3 KDF Entries

IANA is requested to add the values listed in {{kdfid-values}} to the HPKE KDF
Identifiers registry.

--- back

# Test Vectors

Each section below contains test vectors for a single selection of HPKE
algorithms and contains the following values:

1. Configuration information and private key material: This includes the `mode`,
   `info` string, HPKE ciphersuite identifiers (`kem_id`, `kdf_id`, `aead_id`),
   and all sender and recipient key material. For each role S or R, (sender and
   recipient, respectively) key pairs are generated as `(skX, pkX) =
   DeriveKeyPair(ikmX)`.  Each key pair `(skX, pkX)` is written in its
   serialized form, where `skXm = SerializePrivateKey(skX)` and `pkXm =
   SerializePublicKey(pkX)`.  For the PSK mode, the shared PSK and PSK
   identifier are also included.
2. Context creation intermediate values: This includes the KEM outputs `enc` and
   `shared_secret` used to create the context, as well as the context values
   `key`, `base_nonce`, and `exporter_secret`.
3. Encryption test vectors: A fixed plaintext message is encrypted using
   different sequence numbers and AAD values using the context computed in (2).
   Each test vector lists the sequence number and corresponding nonce computed
   with `base_nonce`, the plaintext message `pt`, AAD `aad`, and output
   ciphertext `ct`.
4. Export test vectors: Several exported values of the same length with differing
   context parameters are computed using the context computed in (2). Each test
   vector lists the `exporter_context`, output length `L`, and resulting export
   value.

These test vectors are also available in JSON format at {{TestVectors}}.

{::include test-vectors.md}
