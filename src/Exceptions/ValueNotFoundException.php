<?php

namespace musa11971\JWTDecoder\Exceptions;

use Exception;

class ValueNotFoundException extends Exception
{
    /**
     * ValueNotFoundException constructor.
     *
     * @param $message
     */
    public function __construct($message)
    {
        parent::__construct($message);
    }
}
