<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;

class PrivateKeyFactory
{

    public function createFromConfig(array $config): PrivateKeyContainer
    {
        $result = openssl_pkey_new($config);
        if (!$result) {
            throw new \Exception(openssl_error_string());
        }
        return new PrivateKeyContainer($result);
    }
}