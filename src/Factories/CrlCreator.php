<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Enums\RevokeReasonsEnum;
use JuanchoSL\Certificates\Interfaces\Complex\CertificateInterface;
use JuanchoSL\Certificates\Interfaces\Complex\PrivateKeyInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Repositories\CrlContainer;
use JuanchoSL\Certificates\Traits\SaveableTrait;
use JuanchoSL\Exceptions\PreconditionFailedException;
use JuanchoSL\Exceptions\PreconditionRequiredException;
use Stringable;
use Ukrbublik\openssl_x509_crl\X509;
use Ukrbublik\openssl_x509_crl\X509_CRL;

class CrlCreator implements Stringable, SaveableInterface
{

    use SaveableTrait;

    protected ?PrivateKeyInterface $private = null;
    protected ?CertificateInterface $certificate = null;
    protected CrlContainer $revoked_certs;
    protected int $crl_number = 1;
    protected ?int $days_next_crl = null;

    protected iterable $options = [
        self::CRL_OPTION_VERSION => 2,
        self::CRL_OPTION_DAYS_TO_NEXT => 7,
        self::CRL_OPTION_DISTRIBUTION_FRESH => '',
        self::CRL_OPTION_NUMBER => 1,
        self::CRL_OPTION_SIGN_ALGORITHM => OPENSSL_ALGO_SHA256
    ];

    const CRL_OPTION_VERSION = 'version';
    const CRL_OPTION_NUMBER = 'crl_number';
    const CRL_OPTION_DAYS_TO_NEXT = 'days_next_crl';
    const CRL_OPTION_DISTRIBUTION_FRESH = 'freshest_crl';
    const CRL_OPTION_SIGN_ALGORITHM = 'algo';

    public function __construct(iterable $options)
    {
        foreach ($options as $option => $value) {
            if (array_key_exists($option, $this->options)) {
                $this->options[$option] = $value;
            }
        }
    }

    public function setPrivateKey(#[\SensitiveParameter] PrivateKeyInterface $private): static
    {
        $this->private = $private;
        return $this;
    }

    public function setCertificate(CertificateInterface $certificate): static
    {
        $this->certificate = $certificate;
        return $this;
    }

    public function setCertificates(CrlContainer $revoked_certs): static
    {
        $this->revoked_certs = $revoked_certs;
        $this->options[self::CRL_OPTION_NUMBER] = $revoked_certs->getNumber();
        return $this;
    }

    public function export()
    {
        if (empty($this->private) or empty($this->certificate)) {
            throw new PreconditionRequiredException("The CA private key and his referred certificate are required");
        }
        if (!$this->certificate->checkSubjectPrivateKey($this->private)) {
            throw new PreconditionFailedException("The private key is not referred to this certificate");
        }
        $ci = [
            'no' => $this->options[self::CRL_OPTION_NUMBER],
            'version' => $this->options[self::CRL_OPTION_VERSION],
            'alg' => $this->options[self::CRL_OPTION_SIGN_ALGORITHM],
            'revoked' => []
        ];
        if (!is_null($this->options[self::CRL_OPTION_DISTRIBUTION_FRESH]) && filter_var($this->options[self::CRL_OPTION_DISTRIBUTION_FRESH], FILTER_VALIDATE_URL)) {
            $ci['freshest_crl'] = $this->options[self::CRL_OPTION_DISTRIBUTION_FRESH];
        }
        if (!is_null($this->options[self::CRL_OPTION_DAYS_TO_NEXT]) && is_int($this->options[self::CRL_OPTION_DAYS_TO_NEXT])) {
            $ci['days'] = $this->options[self::CRL_OPTION_DAYS_TO_NEXT];
        }
        if (!empty($this->revoked_certs) && $this->revoked_certs->count() > 0) {
            foreach ($this->revoked_certs as $revoked_cert) {
                $temp = array(
                    'serial' => (is_numeric($revoked_cert['cert'])) ? $revoked_cert['cert'] : (intval((is_string($revoked_cert['cert'])) ? hexdec($revoked_cert['cert']) : $revoked_cert['cert']->getDetail('serialNumber'))),
                    'rev_date' => intval($revoked_cert['rev_date']->getTimestamp()),
                    'compr_date' => strtotime("-1 day"),
                    'reason' => intval(X509::getRevokeReasonCodeByName(($revoked_cert['reason'] == RevokeReasonsEnum::REVOKE_REASON_UNESPECIFIED) ? null : $revoked_cert['reason']->value)),
                    'hold_instr' => null
                );

                $ci['revoked'][] = $temp;
            }
        }
        return X509_CRL::create($ci, $this->private->__invoke(), $this->certificate->export());
    }

    public function __tostring(): string
    {
        return (new ConverterFactory())->convertFromBinaryToPem($this->export(), ContentTypesEnum::CONTENTTYPE_CRL);
    }
}