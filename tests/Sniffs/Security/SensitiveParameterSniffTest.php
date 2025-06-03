<?php declare(strict_types = 1);

namespace Matomo\Sniffs\Security;

use SlevomatCodingStandard\Sniffs\TestCase;

class SensitiveParameterSniffTest extends TestCase
{
    public function testNoErrors(): void
    {
        $report = self::checkFile(__DIR__ . '/data/sensitiveParametersNoErrors.php', [
            'sensitiveKeywords' => [
                'password',
                'passwordNew',
            ],
        ]);

        self::assertNoSniffErrorInFile($report);
    }

    public function testMisplacedAttribute(): void
    {
        $report = self::checkFile(__DIR__ . '/data/sensitiveParametersMisplacedAttribute.php');

        self::assertSniffError(
            $report,
            6,
            'MissingSensitiveParameterAttribute',
            'Parameter $password seems sensitive and has no complex type but is missing #[\SensitiveParameter] attribute.'
        );
    }

    public function testMissingAttribute(): void
    {
        $report = self::checkFile(__DIR__ . '/data/sensitiveParametersMissingAttribute.php');

        self::assertSniffError(
            $report,
            5,
            'MissingSensitiveParameterAttribute',
            'Parameter $password seems sensitive and has no complex type but is missing #[\SensitiveParameter] attribute.'
        );
    }

    public function testWrongAttribute(): void
    {
        $report = self::checkFile(__DIR__ . '/data/sensitiveParametersWrongAttribute.php');

        self::assertSniffError(
            $report,
            7,
            'MissingSensitiveParameterAttribute',
            'Parameter $password seems sensitive and has no complex type but is missing #[\SensitiveParameter] attribute.'
        );
    }
}
