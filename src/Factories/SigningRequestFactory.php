<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Certificates\Repositories\SigningRequestContainer;

class SigningRequestFactory
{

    public function createFromConfig(array $distinguised_names, array $config, #[\SensitiveParameter] PrivateKeyContainer $private): SigningRequestContainer
    {
        $result = openssl_csr_new($distinguised_names, $private, $config);
        if (!$result) {
            throw new \Exception(openssl_error_string());
        }
        return new SigningRequestContainer($result);
    }
}