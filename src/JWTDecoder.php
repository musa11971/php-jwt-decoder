<?php

namespace musa11971\JWTDecoder;

use ArrayAccess;
use DateTime;
use DomainException;
use musa11971\JWTDecoder\Exceptions\BeforeValidException;
use musa11971\JWTDecoder\Exceptions\ExpiredJWTException;
use musa11971\JWTDecoder\Exceptions\InvalidArgumentException;
use musa11971\JWTDecoder\Exceptions\SignatureInvalidException;
use musa11971\JWTDecoder\Exceptions\UnexpectedValueException;

class JWTDecoder
{
    const ASN1_INTEGER = 0x02;
    const ASN1_SEQUENCE = 0x10;

    /**
     * When checking nbf, iat or expiration times,
     * we want to provide some extra leeway time to
     * account for clock skew.
     */
    public static int $leeway = 0;

    /**
     * The token that should be decoded.
     *
     * @var string $token
     */
    public string $token = '';
    /**
     * An array of the keys.
     *
     * @var array $keys
     */
    public array $keys = [];
    /**
     * Decoding options.
     *
     * @var array|false[]
     */
    private array $options = [
        'ignore_expiry' => false,
        'ignore_nbf'    => false
    ];

    /**
     * The timestamp used to validate the token.
     *
     * @var int|null $timestamp
     */
    public ?int $timestamp = null;

    /**
     * An array of the supported algorithms.
     *
     * @var array|\string[][]
     */
    public static array $supported_algs = array(
        'ES256' => array('openssl', 'SHA256'),
        'HS256' => array('hash_hmac', 'SHA256'),
        'HS384' => array('hash_hmac', 'SHA384'),
        'HS512' => array('hash_hmac', 'SHA512'),
        'RS256' => array('openssl', 'SHA256'),
        'RS384' => array('openssl', 'SHA384'),
        'RS512' => array('openssl', 'SHA512'),
    );

    /**
     * JWTDecoder constructor.
     *
     * @param string $token The token that should be decoded.
     */
    private function __construct(string $token)
    {
        $this->token = $token;
    }

    /**
     * Initializes the decoder with a token.
     *
     * @param string $token The token that should be decoded.
     *
     * @return JWTDecoder
     */
    public static function token(string $token): JWTDecoder
    {
        return new self($token);
    }

    /**
     * Adds a key to use for decoding.
     *
     * @param string $key The key that should be used for decoding.
     *
     * @return JWTDecoder
     */
    public function withKey(string $key): JWTDecoder
    {
        $this->keys[] = $key;
        return $this;
    }

    /**
     * Adds multiple keys to use for decoding.
     *
     * @param string[] $keys The keys that should be used for decoding.
     *
     * @return JWTDecoder
     */
    public function withKeys(array $keys): JWTDecoder
    {
        foreach ($keys as $key) {
            $this->withKey($key);
        }

        return $this;
    }

    /**
     * Sets whether to ignore the expiry on the JWT or not.
     *
     * @param bool $ignore A boolean indicating whether to ignore expiry check.
     *
     * @return JWTDecoder
     */
    public function ignoreExpiry(bool $ignore = true): JWTDecoder
    {
        $this->options['ignore_expiry'] = $ignore;
        return $this;
    }

    /**
     * Sets whether to ignore the 'not valid before' on the JWT or not.
     *
     * @param bool $ignore A boolean indicating whether to ignore the 'not valid before' check.
     *
     * @return JWTDecoder
     */
    public function ignoreNotValidBefore(bool $ignore = true): JWTDecoder
    {
        $this->options['ignore_nbf'] = $ignore;
        return $this;
    }

    /**
     * Decodes the JWT with the key(s).
     *
     * @return JWTPayload|null
     *
     * @throws \musa11971\JWTDecoder\Exceptions\BeforeValidException
     * @throws \musa11971\JWTDecoder\Exceptions\ExpiredJWTException
     * @throws \musa11971\JWTDecoder\Exceptions\InvalidArgumentException
     * @throws \musa11971\JWTDecoder\Exceptions\SignatureInvalidException
     * @throws \musa11971\JWTDecoder\Exceptions\UnexpectedValueException
     */
    public function decode(): ?JWTPayload
    {
        foreach ($this->keys as $index => $key) {
            try {
                return $this->decodeWithKey($key);
            }
            catch(SignatureInvalidException $e) {
                /**
                 * If this is the last key to try and it fails with a ..
                 * .. SignatureInvalidException, we will throw so the ..
                 * .. user can deal with it.
                 */
                if ($index == count($this->keys) - 1) {
                    throw $e;
                }

                // Continue to next iteration, so that the next key can be attempted
                continue;
            }
        }
        return null;
    }

    /**
     * Attempt to decode the JWT with the given key.
     *
     * @param string $key
     *
     * @return JWTPayload
     *
     * @throws \musa11971\JWTDecoder\Exceptions\BeforeValidException
     * @throws \musa11971\JWTDecoder\Exceptions\ExpiredJWTException
     * @throws \musa11971\JWTDecoder\Exceptions\InvalidArgumentException
     * @throws \musa11971\JWTDecoder\Exceptions\SignatureInvalidException
     * @throws \musa11971\JWTDecoder\Exceptions\UnexpectedValueException
     */
    private function decodeWithKey(string $key): JWTPayload
    {
        $jwt = $this->token;

        $timestamp = is_null($this->timestamp) ? time() : $this->timestamp;

        if (empty($key)) {
            throw new InvalidArgumentException('Key may not be empty');
        }
        $tks = explode('.', $jwt);
        if (count($tks) != 3) {
            throw new UnexpectedValueException('Wrong number of segments');
        }
        [$headb64, $bodyb64, $cryptob64] = $tks;
        if (null === ($header = static::jsonDecode(static::urlsafeB64Decode($headb64)))) {
            throw new UnexpectedValueException('Invalid header encoding');
        }
        if (null === $payload = static::jsonDecode(static::urlsafeB64Decode($bodyb64))) {
            throw new UnexpectedValueException('Invalid claims encoding');
        }
        if (false === ($sig = static::urlsafeB64Decode($cryptob64))) {
            throw new UnexpectedValueException('Invalid signature encoding');
        }
        if (empty($header->alg)) {
            throw new UnexpectedValueException('Empty algorithm');
        }
        if (empty(static::$supported_algs[$header->alg])) {
            throw new UnexpectedValueException('Algorithm not supported');
        }
        if ($header->alg === 'ES256') {
            // OpenSSL expects an ASN.1 DER sequence for ES256 signatures
            $sig = self::signatureToDER($sig);
        }

        if (is_array($key) || $key instanceof ArrayAccess) {
            if (isset($header->kid)) {
                if (!isset($key[$header->kid])) {
                    throw new UnexpectedValueException('"kid" invalid, unable to lookup correct key');
                }
                $key = $key[$header->kid];
            } else {
                throw new UnexpectedValueException('"kid" empty, unable to lookup correct key');
            }
        }

        // Check the signature
        if (!static::verify("$headb64.$bodyb64", $sig, $key, $header->alg)) {
            throw new SignatureInvalidException('Signature verification failed');
        }

        // Check the nbf if it is defined. This is the time that the
        // token can actually be used. If it's not yet that time, abort.
        if (!$this->options['ignore_nbf']) {
            if (isset($payload->nbf) && $payload->nbf > ($timestamp + static::$leeway)) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->nbf)
                );
            }
        }

        // Check that this token has been created before 'now'. This prevents
        // using tokens that have been created for later use (and haven't
        // correctly used the nbf claim).
        if (!$this->options['ignore_nbf']) {
            if (isset($payload->iat) && $payload->iat > ($timestamp + static::$leeway)) {
                throw new BeforeValidException(
                    'Cannot handle token prior to ' . date(DateTime::ISO8601, $payload->iat)
                );
            }
        }

        // Check if this token has expired.
        if (!$this->options['ignore_expiry']) {
            if (isset($payload->exp) && ($timestamp - static::$leeway) >= $payload->exp) {
                throw new ExpiredJWTException('Expired token');
            }
        }

        return new JWTPayload($payload);
    }

    /**
     * Verify a signature with the message, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string          $msg       The original message (header and body)
     * @param string          $signature The original signature
     * @param string|resource $key       For HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string          $alg       The algorithm
     *
     * @return bool
     *
     * @throws \DomainException Invalid Algorithm or OpenSSL failure
     */
    private static function verify(string $msg, string $signature, $key, string $alg): bool
    {
        if (empty(static::$supported_algs[$alg])) {
            throw new DomainException('Algorithm not supported');
        }

        [$function, $algorithm] = static::$supported_algs[$alg];
        switch ($function) {
        case 'openssl':
            $success = openssl_verify($msg, $signature, $key, $algorithm);
            if ($success === 1) {
                return true;
            } elseif ($success === 0) {
                return false;
            }
            // returns 1 on success, 0 on failure, -1 on error.
            throw new DomainException(
                'OpenSSL error: ' . openssl_error_string()
            );
        case 'hash_hmac':
        default:
            $hash = hash_hmac($algorithm, $msg, $key, true);
            if (function_exists('hash_equals')) {
                return hash_equals($signature, $hash);
            }
            $len = min(static::safeStrlen($signature), static::safeStrlen($hash));

            $status = 0;
            for ($i = 0; $i < $len; $i++) {
                $status |= (ord($signature[$i]) ^ ord($hash[$i]));
            }
            $status |= (static::safeStrlen($signature) ^ static::safeStrlen($hash));

            return ($status === 0);
        }
    }

    /**
     * Get the number of bytes in cryptographic strings.
     *
     * @param string $str The string used to determine the number of bytes.
     *
     * @return int
     */
    private static function safeStrlen(string $str): int
    {
        if (function_exists('mb_strlen')) {
            return mb_strlen($str, '8bit');
        }
        return strlen($str);
    }

    /**
     * Decode a JSON string into a PHP object.
     *
     * @param string $input JSON string
     *
     * @return object Object representation of JSON string
     *
     * @throws \DomainException Provided string was invalid JSON
     */
    public static function jsonDecode(string $input): object
    {
        if (version_compare(PHP_VERSION, '5.4.0', '>=') && !(defined('JSON_C_VERSION') && PHP_INT_SIZE > 4)) {
            // In PHP >=5.4.0, json_decode() accepts an options parameter, that allows you
            // to specify that large ints (like Steam Transaction IDs) should be treated as
            // strings, rather than the PHP default behaviour of converting them to floats.
            $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
        } else {
            // Not all servers will support that, however, so for older versions we must
            // manually detect large ints in the JSON string and quote them (thus converting
            // them to strings) before decoding, hence the preg_replace() call.
            $max_int_length = strlen((string) PHP_INT_MAX) - 1;
            $json_without_bigints = preg_replace('/:\s*(-?\d{'.$max_int_length.',})/', ': "$1"', $input);
            $obj = json_decode($json_without_bigints);
        }

        if ($errno = json_last_error()) {
            static::handleJsonError($errno);
        } elseif ($obj === null && $input !== 'null') {
            throw new DomainException('Null result with non-null input');
        }
        return $obj;
    }

    /**
     * Decode a string with URL-safe Base64.
     *
     * @param string $input A Base64 encoded string
     *
     * @return string A decoded string
     */
    public static function urlsafeB64Decode(string $input): string
    {
        $remainder = strlen($input) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $input .= str_repeat('=', $padlen);
        }
        return base64_decode(strtr($input, '-_', '+/'));
    }

    /**
     * Convert an ECDSA signature to an ASN.1 DER sequence
     *
     * @param string $sig The ECDSA signature to convert
     *
     * @return string The encoded DER object
     */
    private static function signatureToDER(string $sig): string
    {
        // Separate the signature into r-value and s-value
        [$r, $s] = str_split($sig, (int) (strlen($sig) / 2));

        // Trim leading zeros
        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        // Convert r-value and s-value from unsigned big-endian integers to
        // signed two's complement
        if (ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return self::encodeDER(
            self::ASN1_SEQUENCE,
            self::encodeDER(self::ASN1_INTEGER, $r) .
            self::encodeDER(self::ASN1_INTEGER, $s)
        );
    }

    /**
     * Encodes a value into a DER object.
     *
     * @param int    $type  DER tag
     * @param string $value the value to encode
     *
     * @return string the encoded object
     */
    private static function encodeDER(int $type, string $value): string
    {
        $tag_header = 0;
        if ($type === self::ASN1_SEQUENCE) {
            $tag_header |= 0x20;
        }

        // Type
        $der = chr($tag_header | $type);

        // Length
        $der .= chr(strlen($value));

        return $der . $value;
    }

    /**
     * Helper method to create a JSON error.
     *
     * @param int $errno An error number from json_last_error()
     *
     * @return void
     *
     * @throws \DomainException
     */
    private static function handleJsonError(int $errno)
    {
        $messages = array(
            JSON_ERROR_DEPTH => 'Maximum stack depth exceeded',
            JSON_ERROR_STATE_MISMATCH => 'Invalid or malformed JSON',
            JSON_ERROR_CTRL_CHAR => 'Unexpected control character found',
            JSON_ERROR_SYNTAX => 'Syntax error, malformed JSON',
            //PHP >= 5.3.3
            JSON_ERROR_UTF8 => 'Malformed UTF-8 characters'
        );
        throw new DomainException(
            isset($messages[$errno])
                ? $messages[$errno]
                : 'Unknown JSON error: ' . $errno
        );
    }
}
