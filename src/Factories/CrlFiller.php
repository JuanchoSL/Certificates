<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use Countable;
use DateTimeInterface;
use Iterator;
use Stringable;
use JuanchoSL\Certificates\Repositories\CrlContainer;
use JuanchoSL\Certificates\Enums\RevokeReasonsEnum;
use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;

class CrlFiller extends CrlContainer implements Iterator, Countable, Stringable
{

    public function addRevocation(CertificateInterface $cert, DateTimeInterface $revoke_time, ?RevokeReasonsEnum $revoke_reason = null): static
    {
        $this->certs[] = [
            'cert' => $cert,
            'rev_date' => $revoke_time,
            'reason' => $revoke_reason ?? RevokeReasonsEnum::REVOKE_REASON_UNESPECIFIED
        ];
        return $this;
    }

}