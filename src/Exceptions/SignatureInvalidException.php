<?php

namespace musa11971\JWTDecoder\Exceptions;

use Exception;

class SignatureInvalidException extends Exception
{
    /**
     * SignatureInvalidException constructor.
     *
     * @param $message
     */
    public function __construct($message)
    {
        parent::__construct($message);
    }
}
