<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use Countable;
use DateTimeInterface;
use Iterator;
use Stringable;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\CrlContainer;
use JuanchoSL\Certificates\Enums\RevokeReasonsEnum;
use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;

class CrlFiller extends CrlContainer implements Iterator, Countable, Stringable, SaveableInterface, DetailableInterface
{

    public function addRevocation(CertificateInterface $cert, DateTimeInterface $revoke_time, ?RevokeReasonsEnum $revoke_reason = null): static
    {
        if (!$this->updated) {
            $this->number += 1;
            $this->updated = true;
        }
        return $this->appendConvertedData($cert->getDetail('serialNumber'), $revoke_time, $revoke_reason ?? RevokeReasonsEnum::REVOKE_REASON_UNESPECIFIED);
    }

}