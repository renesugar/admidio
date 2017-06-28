<?php

use PHPUnit\Framework\TestCase;

class PasswordHashingTest extends TestCase
{
    /**
     * @return array[]
     */
    public function hashProvider()
    {
        return array(
            array('2y', '12',            'asdfasdf', 'DEFAULT', array()),
            array('2y', '12',            'asdfasdf', 'BCRYPT',  array()),
            array('6',  'rounds=100000', 'asdfasdf', 'SHA512',  array()),
            array('2y', '14',            'asdfasdf', 'DEFAULT', array('cost' => 14)),
            array('2y', '14',            'asdfasdf', 'BCRYPT',  array('cost' => 14)),
            array('6',  'rounds=200000', 'asdfasdf', 'SHA512',  array('cost' => 200000)),
            array('2y', '10',            'asdfasdf', 'DEFAULT', array('cost' => 8)),
            array('2y', '10',            'asdfasdf', 'BCRYPT',  array('cost' => 8)),
            array('6',  'rounds=50000',  'asdfasdf', 'SHA512',  array('cost' => 10000))
        );
    }
    /**
     * @param string $expectedHashFlag
     * @param string $expectedCost
     * @param string $password
     * @param string $algorithm
     * @param array  $options
     * @dataProvider hashProvider
     */
    public function testHash($expectedHashFlag, $expectedCost, $password, $algorithm, array $options)
    {
        $hash = PasswordHashing::hash($password, $algorithm, $options);
        $hashLength = strlen($hash);
        $hashParts = explode('$', $hash);

        $this->assertEquals($expectedHashFlag, $hashParts[1]);
        $this->assertEquals($expectedCost, $hashParts[2]);

        if ($expectedHashFlag === '6')
        {
            $this->assertGreaterThanOrEqual(HASH_LENGTH_SHA512, $hashLength);
        }
        else
        {
            $this->assertEquals(HASH_LENGTH_BCRYPT, $hashLength);
        }
    }

    /**
     * @return array[]
     */
    public function verifyProvider()
    {
        return array(
            array(true,  'asdfasdf', '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(true,  'asdfasdf', '$6$rounds=100000$AhVnPtAQ$1Ovc1XtIpy7QRNrf1McJEGuzbGlh7xMRuaoTLXYXjD2VKSUEOOe.o/LVaImHjuMlbYygFILIoD1YEHkenWN3V/'),
            array(true,  'asdfasdf', '$P$CMfs3G4j/iEC1Av.GpI4G4nezfd0b31'),
            array(true,  'asdfasdf', '6a204bd89f3c8348afd5c77c717a097a'),
            array(false, 'asdfasdf', 'asdfasdf'),
            array(false, 'asdfasdf', '')
        );
    }
    /**
     * @param bool   $expectedResult
     * @param string $password
     * @param string $hash
     * @dataProvider verifyProvider
     */
    public function testVerify($expectedResult, $password, $hash)
    {
        $this->assertEquals($expectedResult, PasswordHashing::verify($password, $hash));
    }

    /**
     * @return array[]
     */
    public function needsRehashProvider()
    {
        return array(
            array(false, 'DEFAULT', array(),                 '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(true,  'DEFAULT', array('cost' => 8),      '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(true,  'DEFAULT', array('cost' => 14),     '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(false, 'BCRYPT',  array(),                 '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(true,  'BCRYPT',  array('cost' => 8),      '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(true,  'BCRYPT',  array('cost' => 14),     '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(true,  'SHA512',  array(),                 '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array(true,  'DEFAULT', array(),                 '$6$rounds=100000$AhVnPtAQ$1Ovc1XtIpy7QRNrf1McJEGuzbGlh7xMRuaoTLXYXjD2VKSUEOOe.o/LVaImHjuMlbYygFILIoD1YEHkenWN3V/'),
            array(true,  'BCRYPT',  array(),                 '$6$rounds=100000$AhVnPtAQ$1Ovc1XtIpy7QRNrf1McJEGuzbGlh7xMRuaoTLXYXjD2VKSUEOOe.o/LVaImHjuMlbYygFILIoD1YEHkenWN3V/'),
            array(false, 'SHA512',  array(),                 '$6$rounds=100000$AhVnPtAQ$1Ovc1XtIpy7QRNrf1McJEGuzbGlh7xMRuaoTLXYXjD2VKSUEOOe.o/LVaImHjuMlbYygFILIoD1YEHkenWN3V/'),
            array(true,  'SHA512',  array('cost' => 5000),   '$6$rounds=100000$AhVnPtAQ$1Ovc1XtIpy7QRNrf1McJEGuzbGlh7xMRuaoTLXYXjD2VKSUEOOe.o/LVaImHjuMlbYygFILIoD1YEHkenWN3V/'),
            array(true,  'SHA512',  array('cost' => 500000), '$6$rounds=100000$AhVnPtAQ$1Ovc1XtIpy7QRNrf1McJEGuzbGlh7xMRuaoTLXYXjD2VKSUEOOe.o/LVaImHjuMlbYygFILIoD1YEHkenWN3V/'),
            array(true,  'DEFAULT', array(),                 '$P$CMfs3G4j/iEC1Av.GpI4G4nezfd0b31'),
            array(true,  'BCRYPT',  array(),                 '$P$CMfs3G4j/iEC1Av.GpI4G4nezfd0b31'),
            array(true,  'SHA512',  array(),                 '$P$CMfs3G4j/iEC1Av.GpI4G4nezfd0b31'),
            array(true,  'DEFAULT', array(),                 '6a204bd89f3c8348afd5c77c717a097a'),
            array(true,  'BCRYPT',  array(),                 '6a204bd89f3c8348afd5c77c717a097a'),
            array(true,  'SHA512',  array(),                 '6a204bd89f3c8348afd5c77c717a097a'),
            array(true,  'DEFAULT', array(),                 'asdfasdf'),
            array(true,  'BCRYPT',  array(),                 'asdfasdf'),
            array(true,  'SHA512',  array(),                 'asdfasdf'),
            array(true,  'DEFAULT', array(),                 ''),
            array(true,  'BCRYPT',  array(),                 ''),
            array(true,  'SHA512',  array(),                 '')
        );
    }
    /**
     * @param bool   $expectedResult
     * @param string $algorithm
     * @param array  $options
     * @param string $hash
     * @dataProvider needsRehashProvider
     */
    public function testNeedsRehash($expectedResult, $algorithm, array $options, $hash)
    {
        $this->assertEquals($expectedResult, PasswordHashing::needsRehash($hash, $algorithm, $options));
    }

    /**
     * @return array[]
     */
    public function getRandomPasswordProvider()
    {
        return array(
            array(false, 0, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            array(false, 1, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            array(false, 10, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'),
            array(false, 0, '0'),
            array(true,  1, '0'),
            array(true,  10, '0'),
            array(false, 0, 'aaaaa'),
            array(true,  1, 'aaaaa'),
            array(true,  10, 'aaaaa'),
            array(false, 0, '0123456789'),
            array(false, 1, '0123456789'),
            array(false, 10, '0123456789'),
            array(false, 0, '!"§$%&'),
            array(false, 1, '!"§$%&'),
            array(false, 10, '!"§$%&')
        );
    }
    /**
     * @param bool   $exception
     * @param int    $length
     * @param string $charset
     * @dataProvider getRandomPasswordProvider
     */
    public function testGetRandomPassword($exception, $length, $charset)
    {
        if ($exception)
        {
            $this->expectException(AdmException::class);
            PasswordHashing::genRandomPassword($length, $charset);
        }
        else
        {
            $randomPassword = PasswordHashing::genRandomPassword($length, $charset);

            $this->assertEquals($length, strlen($randomPassword));
            $this->assertRegExp('/^[' . $charset . ']*$/', $randomPassword);
        }
    }

    /**
     * @return array[]
     */
    public function getRandomIntProvider()
    {
        return array(
            array(0, 0),
            array(-0, 0),
            array(-0, -0),
            array(0, 10),
            array(-10, 0),
            array(-10, 10),
            array(10, 11),
            array(1, 1000)
        );
    }
    /**
     * @param int $min
     * @param int $max
     * @dataProvider getRandomIntProvider
     */
    public function testGetRandomInt($min, $max)
    {
        $randomInt = PasswordHashing::genRandomInt($min, $max);

        $this->assertGreaterThanOrEqual($min, $randomInt);
        $this->assertLessThanOrEqual($max, $randomInt);
    }
    /**
     * @return array[]
     */
    public function getRandomIntErrorExceptionProvider()
    {
        return array(
            array(1, 0),
            array(10, 5)
        );
    }
    /**
     * @param int $min
     * @param int $max
     * @dataProvider getRandomIntErrorExceptionProvider
     * @expectedException PHPUnit_Framework_Error
     */
    public function testGetRandomIntError($min, $max)
    {
        $randomInt = PasswordHashing::genRandomInt($min, $max);

        $this->assertEquals(false, $randomInt);
    }
    /**
     * @param int $min
     * @param int $max
     * @dataProvider getRandomIntErrorExceptionProvider
     * @expectedException              AdmException
     * @expectedExceptionMessageRegExp 'SYS_GEN_RANDOM_ERROR'
     */
    public function testGetRandomIntException($min, $max)
    {
        $randomInt = PasswordHashing::genRandomInt($min, $max, true);
    }

    /**
     * @return array[]
     */
    public function passwordInfoProvider()
    {
        return array(
            array(array('length' => 0,  'number' => false, 'lowerCase' => false, 'upperCase' => false, 'symbol' => false), ''),
            array(array('length' => 4,  'number' => false, 'lowerCase' => true,  'upperCase' => false, 'symbol' => false), 'asdf'),
            array(array('length' => 8,  'number' => true,  'lowerCase' => false, 'upperCase' => true,  'symbol' => false), 'ASDF1234'),
            array(array('length' => 4,  'number' => true,  'lowerCase' => true,  'upperCase' => true,  'symbol' => true ), 'qQ@1'),
            array(array('length' => 21, 'number' => true,  'lowerCase' => false, 'upperCase' => true,  'symbol' => true ), '!"§$%&/()=00000AAAAA')
        );
    }
    /**
     * @param array  $expectedPasswordInfo
     * @param string $password
     * @dataProvider passwordInfoProvider
     */
    public function testPasswordInfo(array $expectedPasswordInfo, $password)
    {
        $this->assertEquals($expectedPasswordInfo, PasswordHashing::passwordInfo($password));
    }

    /**
     * @return array[]
     */
    public function hashInfoProvider()
    {
        return array(
            array(array('algo' => 1, 'algoName' => 'bcrypt', 'options' => array('cost' => 12)), '$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O'),
            array('SHA512', '$6$rounds=100000$AhVnPtAQ$1Ovc1XtIpy7QRNrf1McJEGuzbGlh7xMRuaoTLXYXjD2VKSUEOOe.o/LVaImHjuMlbYygFILIoD1YEHkenWN3V/'),
            array('PRIVATE/PORTABLE_HASH', '$P$CMfs3G4j/iEC1Av.GpI4G4nezfd0b31'),
            array('MD5', '6a204bd89f3c8348afd5c77c717a097a'),
            array('MD5', '6A204BD89F3C8348AFD5C77C717A097A'),
            array('MD5', '12345678901234567890123456789012'),
            array('UNKNOWN', '$P$CMfs3G4j/iEC1Av.GpI4G4nezfd0b310'),
            array('UNKNOWN', '123456789012345678901234567890123'),
            array('UNKNOWN', '6a204bd89f3c8348afd5c77c717a097z'),
            array('UNKNOWN', 'asdfasdf'),
            array('UNKNOWN', '')
        );
    }
    /**
     * @param string|array $expectedHashInfo
     * @param string       $hash
     * @dataProvider hashInfoProvider
     */
    public function testHashInfo($expectedHashInfo, $hash)
    {
        $this->assertEquals($expectedHashInfo, PasswordHashing::hashInfo($hash));
    }

    /**
     * @return array
     */
    public function passwordStrengthProvider()
    {
        $userData = array('test', 'home', 'mustermann', '1234', 'asdf');

        return array(
            array(0, 'testHome', array()),
            array(1, 'testHOME1234Mu', array()),
            array(2, 'aS39LJ', array()),
            array(3, '1234asdfYXCV!"', array()),
            array(4, '1234asdfYXCV!"§$', array()),
            array(0, 'testHome', $userData),
            array(1, '#homeHO1234', $userData),
            array(2, 'aS39LJ', $userData),
            array(3, '1234asdfYXCV!"0000', $userData),
            array(4, '1234asdfYXCV!"§$', $userData)
        );
    }
    /**
     * @param int    $expectedScore
     * @param string $password
     * @param array  $userData
     * @dataProvider passwordStrengthProvider
     */
    public function testPasswordStrength($expectedScore, $password, array $userData)
    {
        $this->assertEquals($expectedScore, PasswordHashing::passwordStrength($password, $userData));
    }


    /**
     * @return array[]
     */
    public function costBenchmarkProvider()
    {
        return array(
            array(0.35, 'password', 'DEFAULT', array('cost' => null)),
            array(0.1,  'password', 'DEFAULT', array('cost' => null)),
            array(1,    'password', 'DEFAULT', array('cost' => null)),
            array(0.35, 'password', 'DEFAULT', array('cost' => 14)),
            array(0.35, 'password', 'DEFAULT', array('cost' => 8)),
            array(0.35, 'password', 'SHA512',  array('cost' => null)),
            array(0.1,  'password', 'SHA512',  array('cost' => null)),
            array(1,    'password', 'SHA512',  array('cost' => null)),
            array(0.35, 'password', 'SHA512',  array('cost' => 500000)),
            array(0.35, 'password', 'SHA512',  array('cost' => 10000))
        );
    }
    /**
     * @param int    $maxTime
     * @param string $password
     * @param string $algorithm
     * @param array  $options
     * @dataProvider costBenchmarkProvider
     */
    public function testCostBenchmark($maxTime, $password, $algorithm, array $options)
    {
        $result = PasswordHashing::costBenchmark($maxTime, $password, $algorithm, $options);

        $defaultMinCost = $options['cost'];

        if ($algorithm === 'SHA512')
        {
            $minCost = HASH_COST_SHA512_MIN;
            $maxCost = HASH_COST_SHA512_MAX;

            if ($defaultMinCost === null)
            {
                $defaultMinCost = HASH_COST_SHA512_DEFAULT;
            }
        }
        else
        {
            $minCost = HASH_COST_BCRYPT_MIN;
            $maxCost = HASH_COST_BCRYPT_MAX;

            if ($defaultMinCost === null)
            {
                $defaultMinCost = HASH_COST_BCRYPT_DEFAULT;
            }
        }

        $this->assertArrayHasKey('cost', $result);
        $this->assertArrayHasKey('time', $result);
        $this->assertInternalType('int', $result['cost']);
        $this->assertInternalType('float', $result['time']);
        $this->assertGreaterThanOrEqual($minCost, $result['cost']);
        $this->assertLessThanOrEqual($maxCost, $result['cost']);
        $this->assertGreaterThan(0, $result['time']);
        // If $result['cost'] is greater than the default or min cost,
        // it could be that $result['time'] is greater than $maxTime
        // >> don't test it
        if ($defaultMinCost < $result['cost'])
        {
            $this->assertLessThanOrEqual($maxTime, $result['time']);
        }
    }
}
