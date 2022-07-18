<?php

declare(strict_types=1);
include_once __DIR__ . '/stubs/Validator.php';
class SNMPValidationTest extends TestCaseSymconValidation
{
    public function testValidateSNMP(): void
    {
        $this->validateLibrary(__DIR__ . '/..');
    }
    public function testValidateSNMPModule(): void
    {
        $this->validateModule(__DIR__ . '/../SNMPAnzeige');
    }
}