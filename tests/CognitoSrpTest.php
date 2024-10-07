<?php

declare(strict_types=1);

namespace CognitoSrpPhp\Tests;

use Aws\Result;
use Carbon\Carbon;
use CognitoSrpPhp\CognitoSrp;
use phpseclib3\Math\BigInteger;
use PHPUnit\Framework\TestCase;
use Random\RandomException;

class CognitoSrpTest extends TestCase
{
    private CognitoSrp $srpHelper;

    protected function setUp(): void
    {
        $this->srpHelper = new CognitoSrp(
            'dummy-client-id',
            'dummy-pool-id'
        );
    }

    /**
     * @throws RandomException
     */
    public function test_calculate_largeAHex(): void
    {
        $largeA = $this->srpHelper->largeAHex();
        $this->assertIsString($largeA);
    }

    public function test_fail_if_cognitoSecretHash_called_without_secret_hash(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('If the user pool has a client secret set, you must pass the `$clientSecret` argument to the constructor');

        $this->srpHelper->cognitoSecretHash('dummy-username');
    }

    public function test_cognitoSecretHash_returns_hash_string(): void
    {
        $this->srpHelper = new CognitoSrp(
            'dummy-client-id',
            'dummy-pool-id',
            'dummy-client-secret'
        );

        $hash = $this->srpHelper->cognitoSecretHash('dummy-username');
        $this->assertSame($hash, 'YkR2p+39v97xkgQcaTJGOZYbowLDT1KQOkJr6YNUI3E=');
    }

    /**
     * @throws RandomException
     */
    public function test_fail_processChallenge_if_unsupported_challengeName_given(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('ChallengeName `SMS_MFA` is not supported.');

        $this->srpHelper = new CognitoSrp(
            'dummy-client-id',
            'dummy-pool-id',
            'dummy-client-secret'
        );
        $mockResult = new Result(['ChallengeName' => 'SMS_MFA']);

        $this->srpHelper->processChallenge($mockResult, 'username', 'password');
    }

    /**
     * @throws RandomException
     */
    public function test_processChallenge(): void
    {
        $mockNow = Carbon::create(2024, 10, 2)->setTimezone('UTC');
        Carbon::setTestNow($mockNow);

        $this->srpHelper = new CognitoSrp(
            'dummy-client-id',
            'dummy-pool-id',
            'dummy-client-secret'
        );
        $mockResult = new Result([
            'ChallengeName' => 'PASSWORD_VERIFIER',
            'ChallengeParameters' => [
                'SALT' => '3b9cadfa7530456cc432931b15bf9951',
                'SECRET_BLOCK' => '0',
                'SRP_B' => '0',
                'USERNAME' => 'dummy-username',
                'USER_ID_FOR_SRP' => 'dummy-username',
            ],
        ]);

        $challenge = $this->srpHelper->processChallenge($mockResult, 'username', 'password');

        $this->assertSame('Wed Oct 2 00:00:00 UTC 2024', $challenge['TIMESTAMP']);
        $this->assertSame('dummy-username', $challenge['USERNAME']);
        $this->assertSame('0', $challenge['PASSWORD_CLAIM_SECRET_BLOCK']);
        $this->assertSame(44, mb_strlen($challenge['PASSWORD_CLAIM_SIGNATURE']));
        $this->assertSame('x2HCZCxHF442chiDvMr3RlnTdu0yLseXaLA398C/m+E=', $challenge['SECRET_HASH']);
    }
}
