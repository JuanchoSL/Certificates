<?php

namespace JuanchoSL\Certificates\Tests\Unit;

use Exception;
use JuanchoSL\Certificates\Interfaces\DetailableInterface;
use JuanchoSL\Certificates\Interfaces\ExportableInterface;
use JuanchoSL\Certificates\Interfaces\FingerprintReadableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordProtectableInterface;
use JuanchoSL\Certificates\Interfaces\PasswordUnprotectableInterface;
use JuanchoSL\Certificates\Interfaces\PublicKeyReadableInterface;
use JuanchoSL\Certificates\Interfaces\SaveableInterface;
use JuanchoSL\Certificates\Interfaces\StandarizableInterface;
use JuanchoSL\Certificates\Repositories\PrivateKeyContainer;
use JuanchoSL\Exceptions\ForbiddenException;
use PHPUnit\Framework\TestCase;
use Stringable;

class PrivateKeyProtectedTest extends TestCase
{

    protected function providerData(): array
    {
        $dir = implode(DIRECTORY_SEPARATOR, [dirname(__FILE__, 3), 'data']) . DIRECTORY_SEPARATOR;
        return [
            'Keyf' => [$dir . 'certificates-crypt.key'],
            'Keys' => [file_get_contents($dir . 'certificates-crypt.key')],
        ];
    }


    /**
     * @dataProvider providerData
     */
    public function testReadNoPasswordContainer($cert)
    {
        $this->expectException(ForbiddenException::class);
        $cert = new PrivateKeyContainer($cert);
    }
    /**
     * @dataProvider providerData
     */
    public function testReadWrongPasswordContainer($cert)
    {
        $this->expectException(Exception::class);
        $cert = new PrivateKeyContainer($cert, 'asdasd');
    }

    /**
     * @dataProvider providerData
     */
    public function testReadContainer($cert)
    {
        $cert = new PrivateKeyContainer($cert, getenv('CRYPT_PASSWORD'));
        $this->assertInstanceOf(PublicKeyReadableInterface::class, $cert);
        $this->assertInstanceOf(DetailableInterface::class, $cert);
        $this->assertInstanceOf(SaveableInterface::class, $cert);
        $this->assertInstanceOf(ExportableInterface::class, $cert);
        $this->assertInstanceOf(StandarizableInterface::class, $cert);
        $this->assertInstanceOf(Stringable::class, $cert);
        $this->assertInstanceOf(PasswordUnprotectableInterface::class, $cert);
        $this->assertNotInstanceOf(FingerprintReadableInterface::class, $cert);
        $this->assertNotInstanceOf(PasswordProtectableInterface::class, $cert);
    }
}