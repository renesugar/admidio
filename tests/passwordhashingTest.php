<?php

use PHPUnit\Framework\TestCase;

class PasswordHashingTest extends TestCase
{
    public function getHashProvider()
    {
        return array(
            array('$2y$12$oCCb222SWprQ5hXLXHuv/.bR9oAaPsD6yh3svXPsN94aNV8Io2W4O', 'asdfasdf')
        );
    }
    /**
     * @dataProvider getHashProvider
     */
//    public function testGetHash($expectedHash, $password)
//    {
//        $hash = PasswordHashing::hash('asdfasdf');
//        $this->assertEquals('asd', $password);
//
//        return $password;
//    }

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
     * @dataProvider verifyProvider
     */
    public function testVerify($expectedResult, $password, $hash)
    {
        $this->assertEquals($expectedResult, PasswordHashing::verify($password, $hash));
    }

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
     * @dataProvider needsRehashProvider
     */
    public function testNeedsRehash($expectedResult, $algorithm, $options, $hash)
    {
        $this->assertEquals($expectedResult, PasswordHashing::needsRehash($hash, $algorithm, $options));
    }

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
            array(1, 1000),
//            array(10, 1)
        );
    }
    /**
     * @dataProvider getRandomIntProvider
     */
    public function testGetRandomInt($min, $max)
    {
        $randomInt = PasswordHashing::genRandomInt($min, $max);

        $this->assertGreaterThanOrEqual($min, $randomInt);
        $this->assertLessThanOrEqual($max, $randomInt);
    }

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
     * @dataProvider passwordInfoProvider
     */
    public function testPasswordInfo($expectedPasswordInfo, $password)
    {
        $this->assertEquals($expectedPasswordInfo, PasswordHashing::passwordInfo($password));
    }

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
     * @dataProvider hashInfoProvider
     */
    public function testHashInfo($expectedHashInfo, $hash)
    {
        $this->assertEquals($expectedHashInfo, PasswordHashing::hashInfo($hash));
    }

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
     * @dataProvider passwordStrengthProvider
     */
    public function testPasswordStrength($expectedScore, $password, $userData)
    {
        $this->assertEquals($expectedScore, PasswordHashing::passwordStrength($password, $userData));
    }
}
