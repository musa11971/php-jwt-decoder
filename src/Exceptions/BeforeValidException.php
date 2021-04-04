<?php

namespace musa11971\JWTDecoder\Exceptions;

use Exception;

class BeforeValidException extends Exception
{
    /**
     * BeforeValidException constructor.
     *
     * @param $message
     */
    public function __construct($message)
    {
        parent::__construct($message);
    }
}
