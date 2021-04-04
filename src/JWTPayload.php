<?php

namespace musa11971\JWTDecoder;

use musa11971\JWTDecoder\Exceptions\ValueNotFoundException;

class JWTPayload
{
    /**
     * The payload data.
     *
     * @var object $_data
     */
    private object $_data;

    /**
     * JWTPayload constructor.
     *
     * @param object $data The object used to create the payload.
     */
    public function __construct(object $data)
    {
        $this->_data = $data;
    }

    /**
     * Gets the value with the given key.
     *
     * @param string $key The key used to get a value from the payload.
     *
     * @return mixed
     * @throws \musa11971\JWTDecoder\Exceptions\ValueNotFoundException
     */
    public function get(string $key)
    {
        if (!$this->has($key)) {
            throw new ValueNotFoundException("Value with key `$key` not found in the JWT payload.");
        }

        return $this->_data->$key;
    }

    /**
     * Checks whether the payload has a value with the given key.
     *
     * @param string $key The key used to check whether the payload has a value.
     *
     * @return bool
     */
    public function has(string $key): bool
    {
        return isset($this->_data->$key);
    }

    /**
     * Converts the JWT payload to an array.
     *
     * @return array
     */
    public function toArray(): array
    {
        return (array) $this->_data;
    }
}
