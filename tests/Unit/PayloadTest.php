<?php

namespace musa11971\JWTDecoder\Tests\Unit;

use musa11971\JWTDecoder\Exceptions\ValueNotFoundException;
use musa11971\JWTDecoder\JWTPayload;
use PHPUnit\Framework\TestCase;

class PayloadTest extends TestCase
{
    /** @test */
    function it_can_check_if_a_value_exists()
    {
        $object = new \stdClass();
        $object->username = 'John';

        $payload = new JWTPayload($object);

        $this->assertTrue($payload->has('username'));
        $this->assertFalse($payload->has('email'));
    }

    /** @test */
    function it_can_get_a_value()
    {
        $object = new \stdClass();
        $object->username = 'John';

        $payload = new JWTPayload($object);

        $this->assertSame('John', $payload->get('username'));
    }

    /** @test */
    function it_cannot_get_a_value_that_does_not_exist()
    {
        $object = new \stdClass();
        $object->username = 'John';

        $payload = new JWTPayload($object);

        $this->expectException(ValueNotFoundException::class);
        $payload->get('email');
    }

    /** @test */
    function it_can_convert_the_payload_to_an_array()
    {
        $object = new \stdClass();
        $object->username = 'John';
        $object->email = 'john@example.com';
        $object->city = 'New York';

        $payload = new JWTPayload($object);

        $this->assertSame([
            'username'  => 'John',
            'email'     => 'john@example.com',
            'city'      => 'New York'
        ], $payload->toArray());
    }
}