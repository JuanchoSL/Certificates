<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits\Bundles;

use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;

trait PrivateKeyTrait
{

    protected $key = null;

    public function getPrivateKey(#[\SensitiveParameter] ?string $password = null): PrivateKeyContainer
    {
        return new PrivateKeyContainer($this->key, $password);
    }
}