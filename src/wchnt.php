<?php

namespace Sodium;

if (!function_exists('Sodium\add')) {


    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_aead_aes256gcm_is_available(): IDK
    {
        return \sodium_crypto_aead_aes256gcm_is_available();
    }

    /**
     * What this function does.
     *
     * @param TYPE $nonce  desc
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_aead_aes256gcm_decrypt($string, $ad, $nonce, $key): IDK
    {
        return \sodium_crypto_aead_aes256gcm_decrypt($string, $ad, $nonce, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $nonce  desc
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_aead_aes256gcm_encrypt($string, $ad, $nonce, $key): IDK
    {
        return \sodium_crypto_aead_aes256gcm_encrypt($string, $ad, $nonce, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $nonce  desc
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_aead_chacha20poly1305_decrypt($string, $ad, $nonce, $key): IDK
    {
        return \sodium_crypto_aead_chacha20poly1305_decrypt($string, $ad, $nonce, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $nonce  desc
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_aead_chacha20poly1305_encrypt($string, $ad, $nonce, $key): IDK
    {
        return \sodium_crypto_aead_chacha20poly1305_encrypt($string, $ad, $nonce, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $nonce  desc
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_aead_chacha20poly1305_ietf_decrypt($string, $ad, $nonce, $key): IDK
    {
        return \sodium_crypto_aead_chacha20poly1305_ietf_decrypt($string, $ad, $nonce, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $nonce  desc
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_aead_chacha20poly1305_ietf_encrypt($string, $ad, $nonce, $key): IDK
    {
        return \sodium_crypto_aead_chacha20poly1305_ietf_encrypt($string, $ad, $nonce, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_auth($string, $key): IDK
    {
        return \sodium_crypto_auth($string, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key       desc
     *
     * @return IDK
     */
    function crypto_auth_verify($signature, $string, $key): IDK
    {
        return \sodium_crypto_auth_verify($signature, $string, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_box($string, $nonce, $key): IDK
    {
        return \sodium_crypto_box($string, $nonce, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_keypair(): IDK
    {
        return \sodium_crypto_box_keypair();
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_seed_keypair($key): IDK
    {
        return \sodium_crypto_box_seed_keypair($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_keypair_from_secretkey_and_publickey($secret_key, $public_key): IDK
    {
        return \sodium_crypto_box_keypair_from_secretkey_and_publickey($secret_key, $public_key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_box_open($string, $nonce, $key): IDK
    {
        return \sodium_crypto_box_open($string, $nonce, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_publickey($key): IDK
    {
        return \sodium_crypto_box_publickey($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_publickey_from_secretkey($key): IDK
    {
        return \sodium_crypto_box_publickey_from_secretkey($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_seal($string, $key): IDK
    {
        return \sodium_crypto_box_seal($string, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_seal_open($string, $key): IDK
    {
        return \sodium_crypto_box_seal_open($string, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_box_secretkey($key): IDK
    {
        return \sodium_crypto_box_secretkey($key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $string_3 desc
     * @param TYPE $string_4 desc
     *
     * @return IDK
     */
    function crypto_kx($string_1, $string_2, $string_3, $string_4): IDK
    {
        return \sodium_crypto_kx($string_1, $string_2, $string_3, $string_4);
    }

    /**
     * What this function does.
     *
     * @param TYPE $length desc
     *
     * @return IDK
     */
    function crypto_generichash($string, $key, $length): IDK
    {
        return \sodium_crypto_generichash($string, $key, $length);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_generichash_init($key, $length): IDK
    {
        return \sodium_crypto_generichash_init($key, $length);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_generichash_update($state, $string): IDK
    {
        return \sodium_crypto_generichash_update($state, $string);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_generichash_final($state, $length): IDK
    {
        return \sodium_crypto_generichash_final($state, $length);
    }

    /**
     * What this function does.
     *
     * @param TYPE $salt     desc
     * @param TYPE $opslimit desc
     * @param TYPE $memlimit desc
     *
     * @return IDK
     */
    function crypto_pwhash($length, $password, $salt, $opslimit, $memlimit): IDK
    {
        return \sodium_crypto_pwhash($length, $password, $salt, $opslimit, $memlimit);
    }

    /**
     * What this function does.
     *
     * @param TYPE $memlimit desc
     *
     * @return IDK
     */
    function crypto_pwhash_str($password, $opslimit, $memlimit): IDK
    {
        return \sodium_crypto_pwhash_str($password, $opslimit, $memlimit);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_pwhash_str_verify($hash, $password): IDK
    {
        return \sodium_crypto_pwhash_str_verify($hash, $password);
    }

    /**
     * What this function does.
     *
     * @param TYPE $salt     desc
     * @param TYPE $opslimit desc
     * @param TYPE $memlimit desc
     *
     * @return IDK
     */
    function crypto_pwhash_scryptsalsa208sha256($length, $password, $salt, $opslimit, $memlimit): IDK
    {
        return \sodium_crypto_pwhash_scryptsalsa208sha256($length, $password, $salt, $opslimit, $memlimit);
    }

    /**
     * What this function does.
     *
     * @param TYPE $memlimit desc
     *
     * @return IDK
     */
    function crypto_pwhash_scryptsalsa208sha256_str($password, $opslimit, $memlimit): IDK
    {
        return \sodium_crypto_pwhash_scryptsalsa208sha256_str($password, $opslimit, $memlimit);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $password): IDK
    {
        return \sodium_crypto_pwhash_scryptsalsa208sha256_str_verify($hash, $password);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_scalarmult($string_1, $string_2): IDK
    {
        return \sodium_crypto_scalarmult($string_1, $string_2);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_secretbox($string, $nonce, $key): IDK
    {
        return \sodium_crypto_secretbox($string, $nonce, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_secretbox_open($string, $nonce, $key): IDK
    {
        return \sodium_crypto_secretbox_open($string, $nonce, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_shorthash($string, $key): IDK
    {
        return \sodium_crypto_shorthash($string, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign($string, $keypair): IDK
    {
        return \sodium_crypto_sign($string, $keypair);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_detached($string, $keypair): IDK
    {
        return \sodium_crypto_sign_detached($string, $keypair);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_ed25519_pk_to_curve25519($key): IDK
    {
        return \sodium_crypto_sign_ed25519_pk_to_curve25519($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_ed25519_sk_to_curve25519($key): IDK
    {
        return \sodium_crypto_sign_ed25519_sk_to_curve25519($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_keypair(): IDK
    {
        return \sodium_crypto_sign_keypair();
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_keypair_from_secretkey_and_publickey($secret_key, $public_key): IDK
    {
        return \sodium_crypto_sign_keypair_from_secretkey_and_publickey($secret_key, $public_key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_open($string, $keypair): IDK
    {
        return \sodium_crypto_sign_open($string, $keypair);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_publickey($key): IDK
    {
        return \sodium_crypto_sign_publickey($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_secretkey($key): IDK
    {
        return \sodium_crypto_sign_secretkey($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_publickey_from_secretkey($key): IDK
    {
        return \sodium_crypto_sign_publickey_from_secretkey($key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_sign_seed_keypair($key): IDK
    {
        return \sodium_crypto_sign_seed_keypair($key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key       desc
     *
     * @return IDK
     */
    function crypto_sign_verify_detached($signature, $string, $key): IDK
    {
        return \sodium_crypto_sign_verify_detached($signature, $string, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_stream($length, $nonce, $key): IDK
    {
        return \sodium_crypto_stream($length, $nonce, $key);
    }

    /**
     * What this function does.
     *
     * @param TYPE $key    desc
     *
     * @return IDK
     */
    function crypto_stream_xor($string, $nonce, $key): IDK
    {
        return \sodium_crypto_stream_xor($string, $nonce, $key);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function randombytes_buf($length): IDK
    {
        return \sodium_randombytes_buf($length);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function randombytes_random16(): IDK
    {
        return \sodium_randombytes_random16();
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function randombytes_uniform($integer): IDK
    {
        return \sodium_randombytes_uniform($integer);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function bin2hex($string): IDK
    {
        return \sodium_bin2hex($string);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function compare($string): IDK
    {
        return \sodium_compare($string);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function hex2bin($string_1, $string_2): IDK
    {
        return \sodium_hex2bin($string_1, $string_2);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function increment($string): IDK
    {
        return \sodium_increment($string);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function add($string_1, $string_2): IDK
    {
        return \sodium_add($string_1, $string_2);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function library_version_major(): IDK
    {
        return \sodium_library_version_major();
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function library_version_minor(): IDK
    {
        return \sodium_library_version_minor();
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function memcmp($string_1, $string_2): IDK
    {
        return \sodium_memcmp($string_1, $string_2);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function memzero($reference, $length): IDK
    {
        return \sodium_memzero($reference, $length);
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function version_string(): IDK
    {
        return \sodium_version_string();
    }

    /**
     * What this function does.
     *
     *
     * @return IDK
     */
    function crypto_scalarmult_base($string_1, $string_2): IDK
    {
        return \sodium_crypto_scalarmult_base($string_1, $string_2);
    }
}