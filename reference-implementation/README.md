Benchmarking HPKE with SHA-3
============================

This repository contains a small reference implementation of HPKE, structured to
allow us to measure the performance impact of changes to HPKE.  Specifically,
proposed mechanisms to integrate SHA3 / SHAKE / XOFs in the "KDF" slot, as
[discussed] on the HPKE mailing list.

The core change involved is in the `KeySchedule` function, and in particular,
the way that the `key`, `base_nonce`, and `exporter_secret` values are derived
from the inputs.  In this experiment, we compare three variations:

* Integrating SHA-3 via HPKE (as [suggested by Deirdre])
* An XOF-based approach with derivation labels (as [suggested by Sophie])
* An XOF-based approach with length-separated outputs (my own invention)

These are benchmarked separately and in the context of HPKE.  For the latter
measurement, we use DHKEM(X25519, HKDF-SHA256) as the KEM, because this is
empirically the fastest of the registered KEMs, and thus will show any key
schedule differences to their greatest advantage.  Also looked at ML-KEM-768
because [Deirdre asked].

# Local Measurement Results

```
> cargo bench
```

Environment:

* MacBook M1 Pro, vintage 2021
* Rust 1.85.1
* Rust Crypto and X25519-Dalek used for underlying primitives
* ☁️  Weather: 25C and cloudy 
* 🌘 Moon phase: Waning crescent, 7% illumination

Measurements reflect the mean value measured by Criterion.

| Key schedule variant | KDF / XOF      | Raw        | X225519 Encap | ML-KEM-768 Encap | ML-KEM-768 Decap |
|----------------------|----------------|------------|---------------|------------------|------------------|
| RFC                  | HKDF-SHA256    | 13.018 µs  | 56.667 µs     | 37.105 µs        | 44.695 µs        |
| RFC                  | HKDF-SHA3\_256 | 10.621 µs  | 57.520 µs     | 38.055 µs        | 45.664 µs        |
| XOF with label       | SHAKE128       | 4.3962 µs  | 52.200 µs     | 32.883 µs        | 40.577 µs        |
| XOF with label       | TurboSHAKE128  | 2.4187 µs  | 51.101 µs     | 31.772 µs        | 39.483 µs        |
| XOF with label       | HKDF-SHA256*   | 10.151 µs  | 54.921 µs     | 35.184 µs        | 43.498 µs        |
| XOF with length      | SHAKE128       | 3.5342 µs  | 50.754 µs     | 30.865 µs        | 39.071 µs        |
| XOF with length      | TurboSHAKE128  | 1.9031 µs  | 50.560 µs     | 30.849 µs        | 39.180 µs        |
| XOF with length      | HKDF-SHA256*   | 8.7060 µs  | 52.993 µs     | 33.414 µs        | 41.735 µs        |

("HKDF-SHA256*" meaning "HKDF used as an XOF": The "absorb" operation
corresponds to feeding IKM data into the Extract HMAC.  The "squeeze" operation
corresponds to Expand.  The Salt and Info inputs are empty.)

[discussed]: https://mailarchive.ietf.org/arch/msg/cfrg/zwpQRXtlqnPC0QzJ1-pNbz5ohcM/
[suggested by Deirdre]: https://datatracker.ietf.org/doc/draft-connolly-cfrg-sha3-hpke
[suggested by Sophie]: https://mailarchive.ietf.org/arch/msg/cfrg/3RzIoQs0u5aw-uywoQQoY2gJtbM/
[Deirdre asked]: https://mailarchive.ietf.org/arch/msg/cfrg/hUUdjQYZt0ZRwGTAAhlt7UkK25Q/
