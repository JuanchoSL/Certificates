<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Traits;

use Stringable;

trait SaveableTrait
{

    public function save(?string &$fullpath = null): bool
    {
        $fullpath ??= tempnam(sys_get_temp_dir(), 'crt');
        $function = ($this instanceof Stringable) ? "__tostring" : 'export';
        return (file_put_contents($fullpath, call_user_func([$this, $function])) > 0);
    }

}