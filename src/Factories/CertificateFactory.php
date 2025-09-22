<?php declare(strict_types=1);

namespace JuanchoSL\Certificates\Factories;

use JuanchoSL\Certificates\Enums\ContentTypesEnum;
use JuanchoSL\Certificates\Repositories\CertificateContainer;
use JuanchoSL\Validators\Types\Strings\StringValidation;

class CertificateFactory
{

    public function readCertificateFromBinary(string $data): CertificateContainer
    {
        return new CertificateContainer((new ConverterFactory())->convertFromBinaryToPem($data, ContentTypesEnum::CONTENTTYPE_CERTIFICATE));
    }

    public function readCertificateFromUrl(string $hostname): CertificateContainer
    {
        if (StringValidation::isUrl($hostname)) {
            $port = parse_url($hostname, PHP_URL_PORT) ?? 443;
            $hostname = parse_url($hostname, PHP_URL_HOST);
        }
        $ssloptions = array(
            "capture_peer_cert" => true,
            "capture_peer_cert_chain" => false,
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
        return new CertificateContainer(stream_context_get_params($result)["options"]["ssl"]["peer_certificate"]);
    }
}
