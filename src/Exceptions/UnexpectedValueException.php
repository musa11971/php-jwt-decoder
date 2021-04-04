<?php

namespace musa11971\JWTDecoder\Exceptions;

use Exception;

class UnexpectedValueException extends Exception
{
    /**
     * UnexpectedValueException constructor.
     *
     * @param $message
     */
    public function __construct($message)
    {
        parent::__construct($message);
    }
}
