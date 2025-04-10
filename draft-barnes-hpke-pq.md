---
title: "TODO - Your title"
abbrev: "TODO - Abbreviation"
category: info

docname: draft-barnes-hpke-pq-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: ""
workgroup: "HPKE Publication, Kept Efficient"
keyword:
 - next generation
 - unicorn
 - sparkling distributed ledger
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
    organization: Your Organization Here
    email: "rlb@ipv.sx"

normative:
    FIPS186: DOI.10.6028/NIST.FIPS.186-5
    FIPS203: DOI.10.6028/NIST.FIPS.203

informative:


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
respect to attack by a quantum computer.

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

It is thus a high priority for many organizations right not to migrate key
exchange technologies to use "post-quantum" (PQ) algorithms, which are resistant
to attack by a quantum computer {{?I-D.ietf-pquip-engineers}}.  Since these PQ
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

# Pure Post-Quantum KEMs

[[ TODO: Map ML-KEM to HPKE API, register 768 and 1024 ]]

# Post-Quantum/Traditional Hybrid KEMs

[[ TODO: DHKEM + ML-KEM, in appropriate combinations ]]

[[ TODO: Define HPKE API methods for the combination (just concatenating) ]]

# SHA-3 as an HPKE KDF

[[ TODO: Defer until draft-ietf-hpke-hpke has a suitable definition ]]

# Selection of AEAD algorithms

[[ TODO: Note that there's no need for new algorithms here; just use the longer
key lengths ]]

# Security Considerations

As discussed in the HPKE Security Considerations, HPKE is an IND-CCA2 secure
public-key encryption scheme if the KEM it uses is IND-CCA2 secure.  It follows
that HPKE is IND-CCA2 secure against a quantum attacker if it uses a KEM that
provides IND-CCA2 security against a quantum attacker, i.e., a PQ KEM.  The KEM
algorithms defined in this document provide this level of security.  ML-KEM
itself is IND-CCA2 secure, and the IND-CCA2 security of the hybrid constructions
used in this document is established in {{!I-D.irtf-cfrg-kem-combiners}}.

[[ TODO: Binding properties ]]

# IANA Considerations

[[ TODO: Register KEM values ]]

[[ TODO: Register KDF values ]]


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
