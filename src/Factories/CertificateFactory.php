<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Certificates\Repositories\ChainContainer;
use JuanchoSL\Validators\Types\Strings\StringValidation;

class CertificateFactory
{

    public function readCertificateFromBinary(string $data): CertificateContainer
    {
        return new CertificateContainer((new ConverterFactory())->convertFromBinaryToPem($data, ContentTypesEnum::CONTENTTYPE_CERTIFICATE));
    }

    public function readCertificateFromUrl(string $hostname): CertificateContainer
    {
        return $this->readDataFromRemote($hostname, false);
    }

    public function readChainFromUrl(string $hostname): ChainContainer
    {
        return $this->readDataFromRemote($hostname, true);
    }

    protected function readDataFromRemote(string $hostname, bool $full_chain = false): CertificateContainer|ChainContainer
    {
        if (StringValidation::isUrl($hostname)) {
            $port = parse_url($hostname, PHP_URL_PORT) ?? 443;
            $hostname = parse_url($hostname, PHP_URL_HOST);
        }
        $ssloptions = array(
            "capture_peer_cert" => true,
            "capture_peer_cert_chain" => $full_chain,
            "allow_self_signed" => false,
            "CN_match" => $hostname,
            "verify_peer" => false,
            "SNI_enabled" => true,
            "SNI_server_name" => $hostname,
        );
        $ctx = stream_context_create(array("ssl" => $ssloptions));
        if (($result = @stream_socket_client("ssl://{$hostname}:{$port}", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $ctx)) === false) {
            throw new \Exception($errstr, $errno);
        }
        $data = stream_context_get_params($result)["options"]["ssl"];

        if ($full_chain) {
            $response = $data['peer_certificate_chain'];
            return new ChainContainer($response);
        } else {
            return new CertificateContainer($data["peer_certificate"]);
        }
    }
}
