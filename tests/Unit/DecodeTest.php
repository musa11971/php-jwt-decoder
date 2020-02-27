<?php

namespace musa11971\JWTDecoder\Tests\Unit;

use Firebase\JWT\JWT;
use musa11971\JWTDecoder\Exceptions\BeforeValidException;
use musa11971\JWTDecoder\Exceptions\ExpiredJWTException;
use musa11971\JWTDecoder\Exceptions\SignatureInvalidException;
use musa11971\JWTDecoder\Exceptions\UnexpectedValueException;
use musa11971\JWTDecoder\JWTDecoder;
use musa11971\JWTDecoder\Tests\Support\Traits\ProvidesRS256KeySet;
use PHPUnit\Framework\TestCase;

class DecodeTest extends TestCase
{
    use ProvidesRS256KeySet;

    /** @test */
    function it_can_decode_a_JWT_using_RS256()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->decode();

        $this->assertSame($payload, $decoded->toArray());
    }

    /** @test */
    function it_can_decode_a_JWT_that_expires_in_the_future()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'exp' => time() + 500
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->decode();

        $this->assertSame($payload, $decoded->toArray());
    }

    /** @test */
    function it_cannot_decode_a_JWT_that_has_expired()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'exp' => time()
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $this->expectException(ExpiredJWTException::class);

        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->decode();
    }

    /** @test */
    function it_can_decode_a_JWT_that_has_expired_with_the_ignoreExpiry_option()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'exp' => time()
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->ignoreExpiry()
            ->decode();

        $this->assertSame($payload, $decoded->toArray());
    }

    /** @test */
    function it_can_decode_a_JWT_that_has_a_nbf_in_the_past()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => time() - 20
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->decode();

        $this->assertSame($payload, $decoded->toArray());
    }

    /** @test */
    function it_cannot_decode_a_JWT_that_has_a_nbf_in_the_future()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => time() + 20
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $this->expectException(BeforeValidException::class);

        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->decode();
    }

    /** @test */
    function it_can_decode_a_JWT_that_has_a_nbf_in_the_future_with_the_ignoreNotValidBefore_option()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => time() + 20
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->ignoreNotValidBefore()
            ->decode();

        $this->assertSame($payload, $decoded->toArray());
    }

    /** @test */
    function it_cannot_decode_a_JWT_with_invalid_segments()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256') . '.extra_seg';

        // Decode the token
        $this->expectException(UnexpectedValueException::class);

        $decoded = JWTDecoder::token($jwt)
            ->withKey($this->RS256KeySet['public-key'])
            ->decode();
    }

    /** @test */
    function it_can_decode_a_JWT_by_attempting_multiple_keys()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => time()
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $decoded = JWTDecoder::token($jwt)
            ->withKeys($this->RS256KeySet['multiple-public-keys'])
            ->decode();

        $this->assertSame($payload, $decoded->toArray());
    }

    /** @test */
    function it_cannot_decode_a_JWT_by_attempting_multiple_invalid_keys()
    {
        // Use Firebase\JWT to generate a JWT
        $payload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => time()
        ];

        $jwt = JWT::encode($payload, $this->RS256KeySet['private-key'], 'RS256');

        // Decode the token
        $this->expectException(SignatureInvalidException::class);

        $decoded = JWTDecoder::token($jwt)
            ->withKeys($this->RS256KeySet['multiple-invalid-public-keys'])
            ->decode();
    }
}