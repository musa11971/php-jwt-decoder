<?php

namespace musa11971\JWTDecoder\Exceptions;

use Exception;

class BeforeValidException extends Exception
{
    public function __construct($message)
    {
        parent::__construct($message);
    }
}