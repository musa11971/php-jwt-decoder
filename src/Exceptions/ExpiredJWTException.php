<?php

namespace musa11971\JWTDecoder\Exceptions;

use Exception;

class ExpiredJWTException extends Exception
{
    /**
     * ExpiredJWTException constructor.
     *
     * @param $message
     */
    public function __construct($message)
    {
        parent::__construct($message);
    }
}
