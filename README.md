Info
====

This tool allows you to take a redeemScript as a template and, using basic
EC math, replace public keys with ones which are only spendable by the original
key's private key holder and which cryptographically commit to the contract
hash specified. In this way, it provides a transparent and undetectable way of
sending payments which commit to some data without adding extra data to the
chain. It does, however, require some small amount of out-of-band communication.

This implements the neccessary parts of appendix A of the sidechains whitepaper,
though it is generally useful in many other cases.

To build
========

Install https://github.com/bitcoin/secp256k1

Use ldconfig so that the ld cache knows about the existence of secp256k1.
