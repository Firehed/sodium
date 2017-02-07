<?php

namespace Sodium;

function crypto_auth(...$args)
{
    return \sodium_crypto_auth(...$args);
}

function crypto_auth_verify(...$args)
{
    return \sodium_crypto_auth_verify(...$args);
}

function crypto_box(...$args)
{
    return \sodium_crypto_box(...$args);
}

function crypto_box_open(...$args)
{
    return \sodium_crypto_box_open(...$args);
}

function crypto_scalarmult(...$args)
{
    return \sodium_crypto_scalarmult(...$args);
}

function crypto_secretbox(...$args)
{
    return \sodium_crypto_secretbox(...$args);
}

function crypto_secretbox_open(...$args)
{
    return \sodium_crypto_secretbox_open(...$args);
}

function crypto_sign(...$args)
{
    return \sodium_crypto_sign(...$args);
}

function crypto_sign_open(...$args)
{
    return \sodium_crypto_sign_open(...$args);
}

function crypto_aead_chacha20poly1305_encrypt(...$args)
{
    return \sodium_crypto_aead_chacha20poly1305_encrypt(...$args);
}

function crypto_aead_chacha20poly1305_decrypt(...$args)
{
    return \sodium_crypto_aead_chacha20poly1305_decrypt(...$args);
}

function crypto_aead_chacha20poly1305_ietf_encrypt(...$args)
{
    return \sodium_crypto_aead_chacha20poly1305_ietf_encrypt(...$args);
}

function crypto_aead_chacha20poly1305_ietf_decrypt(...$args)
{
    return \sodium_crypto_aead_chacha20poly1305_ietf_decrypt(...$args);
}

function crypto_box_keypair(...$args)
{
    return \sodium_crypto_box_keypair(...$args);
}

function crypto_box_keypair_from_secretkey_and_publickey(...$args)
{
    return \sodium_crypto_box_keypair_from_secretkey_and_publickey(...$args);
}

function crypto_box_publickey(...$args)
{
    return \sodium_crypto_box_publickey(...$args);
}

function crypto_box_publickey_from_secretkey(...$args)
{
    return \sodium_crypto_box_publickey_from_secretkey(...$args);
}

function crypto_box_seal(...$args)
{
    return \sodium_crypto_box_seal(...$args);
}

function crypto_box_seal_open(...$args)
{
    return \sodium_crypto_box_seal_open(...$args);
}

function crypto_box_secretkey(...$args)
{
    return \sodium_crypto_box_secretkey(...$args);
}

function crypto_generichash(...$args)
{
    return \sodium_crypto_generichash(...$args);
}

function crypto_generichash_init(...$args)
{
    return \sodium_crypto_generichash_init(...$args);
}

function crypto_generichash_update(...$args)
{
    return \sodium_crypto_generichash_update(...$args);
}

function crypto_generichash_final(...$args)
{
    return \sodium_crypto_generichash_final(...$args);
}

function crypto_kx(...$args)
{
    return \sodium_crypto_kx(...$args);
}

function crypto_pwhash(...$args)
{
    return \sodium_crypto_pwhash(...$args);
}

function crypto_pwhash_str(...$args)
{
    return \sodium_crypto_pwhash_str(...$args);
}

function crypto_pwhash_str_verify(...$args)
{
    return \sodium_crypto_pwhash_str_verify(...$args);
}

function crypto_shorthash(...$args)
{
    return \sodium_crypto_shorthash(...$args);
}

function crypto_sign_detached(...$args)
{
    return \sodium_crypto_sign_detached(...$args);
}

function crypto_sign_keypair(...$args)
{
    return \sodium_crypto_sign_keypair(...$args);
}

function crypto_sign_publickey(...$args)
{
    return \sodium_crypto_sign_publickey(...$args);
}

function crypto_sign_publickey_from_secretkey(...$args)
{
    return \sodium_crypto_sign_publickey_from_secretkey(...$args);
}

function crypto_sign_secretkey(...$args)
{
    return \sodium_crypto_sign_secretkey(...$args);
}

function crypto_sign_verify_detached(...$args)
{
    return \sodium_crypto_sign_verify_detached(...$args);
}

function crypto_stream(...$args)
{
    return \sodium_crypto_stream(...$args);
}

function crypto_stream_xor(...$args)
{
    return \sodium_crypto_stream_xor(...$args);
}

function compare(...$args)
{
    return \sodium_compare(...$args);
}

function memzero(...$args)
{
    return \sodium_memzero(...$args);
}

function increment(...$args)
{
    return \sodium_increment(...$args);
}


const CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES;

const CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NSECBYTES;

const CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_NPUBBYTES;

const CRYPTO_AEAD_CHACHA20POLY1305_ABYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_ABYTES;

const CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_KEYBYTES;

const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NSECBYTES;

const CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES;

const CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES = \SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES;

const CRYPTO_AUTH_BYTES = \SODIUM_CRYPTO_AUTH_BYTES;

const CRYPTO_AUTH_KEYBYTES = \SODIUM_CRYPTO_AUTH_KEYBYTES;

const CRYPTO_BOX_SEALBYTES = \SODIUM_CRYPTO_BOX_SEALBYTES;

const CRYPTO_BOX_SECRETKEYBYTES = \SODIUM_CRYPTO_BOX_SECRETKEYBYTES;

const CRYPTO_BOX_PUBLICKEYBYTES = \SODIUM_CRYPTO_BOX_PUBLICKEYBYTES;

const CRYPTO_BOX_KEYPAIRBYTES = \SODIUM_CRYPTO_BOX_KEYPAIRBYTES;

const CRYPTO_BOX_MACBYTES = \SODIUM_CRYPTO_BOX_MACBYTES;

const CRYPTO_BOX_NONCEBYTES = \SODIUM_CRYPTO_BOX_NONCEBYTES;

const CRYPTO_BOX_SEEDBYTES = \SODIUM_CRYPTO_BOX_SEEDBYTES;

const CRYPTO_KX_BYTES = \SODIUM_CRYPTO_KX_BYTES;

const CRYPTO_KX_PUBLICKEYBYTES = \SODIUM_CRYPTO_KX_PUBLICKEYBYTES;

const CRYPTO_KX_SECRETKEYBYTES = \SODIUM_CRYPTO_KX_SECRETKEYBYTES;

const CRYPTO_GENERICHASH_BYTES = \SODIUM_CRYPTO_GENERICHASH_BYTES;

const CRYPTO_GENERICHASH_BYTES_MIN = \SODIUM_CRYPTO_GENERICHASH_BYTES_MIN;

const CRYPTO_GENERICHASH_BYTES_MAX = \SODIUM_CRYPTO_GENERICHASH_BYTES_MAX;

const CRYPTO_GENERICHASH_KEYBYTES = \SODIUM_CRYPTO_GENERICHASH_KEYBYTES;

const CRYPTO_GENERICHASH_KEYBYTES_MIN = \SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MIN;

const CRYPTO_GENERICHASH_KEYBYTES_MAX = \SODIUM_CRYPTO_GENERICHASH_KEYBYTES_MAX;

const CRYPTO_PWHASH_SALTBYTES = \SODIUM_CRYPTO_PWHASH_SALTBYTES;

const CRYPTO_PWHASH_STRPREFIX = \SODIUM_CRYPTO_PWHASH_STRPREFIX;

const CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE = \SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;

const CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE = \SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;

const CRYPTO_PWHASH_OPSLIMIT_MODERATE = \SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;

const CRYPTO_PWHASH_MEMLIMIT_MODERATE = \SODIUM_CRYPTO_PWHASH_MEMLIMIT_MODERATE;

const CRYPTO_PWHASH_OPSLIMIT_SENSITIVE = \SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE;

const CRYPTO_PWHASH_MEMLIMIT_SENSITIVE = \SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE;

const CRYPTO_SCALARMULT_BYTES = \SODIUM_CRYPTO_SCALARMULT_BYTES;

const CRYPTO_SCALARMULT_SCALARBYTES = \SODIUM_CRYPTO_SCALARMULT_SCALARBYTES;

const CRYPTO_SHORTHASH_BYTES = \SODIUM_CRYPTO_SHORTHASH_BYTES;

const CRYPTO_SHORTHASH_KEYBYTES = \SODIUM_CRYPTO_SHORTHASH_KEYBYTES;

const CRYPTO_SECRETBOX_KEYBYTES = \SODIUM_CRYPTO_SECRETBOX_KEYBYTES;

const CRYPTO_SECRETBOX_MACBYTES = \SODIUM_CRYPTO_SECRETBOX_MACBYTES;

const CRYPTO_SECRETBOX_NONCEBYTES = \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

const CRYPTO_SIGN_BYTES = \SODIUM_CRYPTO_SIGN_BYTES;

const CRYPTO_SIGN_SEEDBYTES = \SODIUM_CRYPTO_SIGN_SEEDBYTES;

const CRYPTO_SIGN_PUBLICKEYBYTES = \SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES;

const CRYPTO_SIGN_SECRETKEYBYTES = \SODIUM_CRYPTO_SIGN_SECRETKEYBYTES;

const CRYPTO_SIGN_KEYPAIRBYTES = \SODIUM_CRYPTO_SIGN_KEYPAIRBYTES;

const CRYPTO_STREAM_KEYBYTES = \SODIUM_CRYPTO_STREAM_KEYBYTES;

const CRYPTO_STREAM_NONCEBYTES = \SODIUM_CRYPTO_STREAM_NONCEBYTES;
