<?php

namespace musa11971\JWTDecoder;

use musa11971\JWTDecoder\Exceptions\ValueNotFoundException;

class JWTPayload
{
    /** @var Object $data */
    private $data;

    public function __construct($data)
    {
        $this->data = $data;
    }

    /**
     * Gets the value with the given key.
     *
     * @param string $key
     * @return mixed
     * @throws null
     */
    public function get($key)
    {
        if(!$this->has($key))
            throw new ValueNotFoundException("Value with key `$key` not found in the JWT payload.");

        return $this->data->$key;
    }

    /**
     * Checks whether the payload has a value with the given key.
     *
     * @param string $key
     * @return bool
     */
    public function has($key)
    {
        return isset($this->data->$key);
    }

    /**
     * Converts the JWT payload to an array.
     *
     * @return array
     */
    public function toArray()
    {
        return (array) $this->data;
    }
}