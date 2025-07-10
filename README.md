<!-- regenerate: on (set to off if you edit this file) -->

# Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE

This is the working area for the individual Internet-Draft, "Post-Quantum and Post-Quantum/Traditional Hybrid Algorithms for HPKE".

* [Editor's Copy](https://hpkewg.github.io/hpke-pq/#go.draft-ietf-hpke-pq.html)
* [Datatracker Page](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq)
* [Individual Draft](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq)
* [Compare Editor's Copy to Individual Draft](https://hpkewg.github.io/hpke-pq/#go.draft-ietf-hpke-pq.diff)


## Contributing

See the
[guidelines for contributions](https://github.com/hpkewg/hpke-pq/blob/main/CONTRIBUTING.md).

Contributions can be made by creating pull requests.
The GitHub interface supports creating pull requests using the Edit (✏) button.


## Command Line Usage

Formatted text and HTML versions of the draft can be built using `make`.

```sh
$ make
```

Command line usage requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/main/doc/SETUP.md).

## Reference Implementation

The `reference-implementation` directory contains reference implementations of
the algorithms defined in this document.  For the PQ/T hybrids, it uses the
reference implementation in [the repository for that
specification](https://github.com/cfrg/draft-irtf-cfrg-concrete-hybrid-kems/).
Since these crates are not published, if you want to use the reference
implementation, you will need to make your own clone of that repo and adjust the
`path` in Cargo.toml to point to it.
