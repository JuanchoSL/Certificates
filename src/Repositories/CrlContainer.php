<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Repositories;

use Countable;
use DateTime;
use DateTimeInterface;
use Iterator;
use Stringable;
use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Traits\DetailableTrait;
use JuanchoSL\Certificates\Traits\FingerprintTrait;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Certificates\Enums\RevokeReasonsEnum;
use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Factories\ConverterFactory;
use JuanchoSL\Certificates\Traits\IterableTrait;
use JuanchoSL\Certificates\Traits\StringableTrait;
use Ukrbublik\openssl_x509_crl\X509;
use vakata\asn1\structures\CRL;

class CrlContainer implements Iterator, Countable, Stringable, DetailableInterface, SaveableInterface, ExportableInterface, FingerprintReadableInterface
{
    use IterableTrait, StringableTrait, DetailableTrait, SaveableTrait, FingerprintTrait;

    protected array $certs = [];
    protected string $data;
    protected int $number = 0;
    protected bool $updated = false;

    public function __construct(string $cert_content)
    {
        $this->certs = [];
        if (is_string($cert_content)) {
            if (is_file($cert_content) && file_exists($cert_content)) {
                $cert_content = file_get_contents($cert_content);
            }
            if (str_contains($cert_content, chr(0)) === false) {
                $cert_content = (new ConverterFactory())->convertFromPemToBinary($cert_content, ContentTypesEnum::CONTENTTYPE_CRL);
            }
        }
        $this->data = $cert_content;
        $this->certs = CRL::fromString($cert_content)->toArray();//['tbsCertList']['revokedCertificates'];
        foreach ($this->certs['tbsCertList']['extensions'] as $extension) {
            if ($extension['extnID'] == '2.5.29.20') {
                $this->number = bindec(current($extension['extnValue']));
            }
        }
        foreach ($this->certs['tbsCertList']['revokedCertificates'] as $cert) {
            $reason = null;
            foreach ($cert['extensions'] as $r_extension) {
                if ($r_extension['extnID'] == '2.5.29.21') {
                    $reason = current($r_extension['extnValue']);
                    $reason = X509::getRevokeReasonNameByCode($reason);
                    if (!is_null($reason)) {
                        $reason = RevokeReasonsEnum::tryFrom($reason);
                    }
                    break;
                }
            }
            $this->appendConvertedData(intval(hexdec($cert['userCertificate'])), new DateTime(date("Y-m-d H:i:s", $cert['revocationDate'])), $reason);
        }
    }

    protected function appendConvertedData(int $serial, DateTimeInterface $revocation_date, ?RevokeReasonsEnum $reason = null): self
    {
        $this->iterable[$serial] = [
            'cert' => $serial,
            'rev_date' => $revocation_date,
            'reason' => $reason
        ];
        return $this;
    }

    public function export(): string
    {
        return $this->data;
    }

    public function __tostring(): string
    {
        return (new ConverterFactory())->convertFromBinaryToPem($this->export(), ContentTypesEnum::CONTENTTYPE_CRL);
    }

    public function getDetails(): array
    {
        return $this->certs;
    }

    public function getNumber()
    {
        return $this->number;
    }

    public function getExtension(): string
    {
        return 'crl';
    }

    public function getMediaType(): string
    {
        return 'application/pkix-crl';
    }

    public function hasCertificate(CertificateInterface $certificate): bool
    {
        return $this->hasSerial(intval($certificate->getDetail('serialNumber')));
    }

    public function hasSerial(int $serial): bool
    {
        return array_key_exists($serial, $this->iterable);
    }

    public function isRevokedByCert(CertificateInterface $cert): bool
    {
        return $this->isRevokedBySerial(intval($cert->getDetail('serialNumber')));
    }

    public function isRevokedBySerial(int $serial): bool
    {
        return ($this->hasSerial($serial) && $this->iterable[$serial]['rev_date']->getTimestamp() <= time());
    }
}