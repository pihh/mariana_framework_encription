<?php

/**
 | Creator: Filipe Mota de Sá - pihh.rocks@gmail.com
 | Date: 1/15/2016
 | Time: 9:30 PM
 | Requires:
 |  .env file with proper variables set or $_ENV[] previously defined
 |  $_ENV['KEY_64'] -> base64 with 64 characters key
 |
 */

class mEncription {

    /**
    |---------------------------
    | Properties & Variables
    |---------------------------
    */

    //private static $mode = 'MCRYPT_BLOWFISH';
    private static $mode = 'BCRYPT';
    private static $key64 = '';

    /**
    |---------------------------
    | If base 64 key doesn't exit, gets it from .env
    | @
    |---------------------------
    */

    public static function setKey(){
        if(static::$key64 == '') {
            static::$key64 = $_ENV['KEY64'];
        }
    }

    /**
    |---------------------------
    | Encripts a key
    | @Params: key : string
    | @Notes: Difference between encription and hash is that encription is a two way process,
    |   as it is made so the key can be achieved without guessing.
    |---------------------------
     */

    public static function encript($encrypt){

        #  Set the encription key
        self::setKey();

        #  Threat the key
        $encrypt = serialize($encrypt);
        $iv = mcrypt_create_iv(mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC), MCRYPT_DEV_URANDOM);
        $key = pack('H*', static::$key64);
        $mac = hash_hmac('sha256', $encrypt, substr(bin2hex($key), -32));
        $passcrypt = mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $encrypt.$mac, MCRYPT_MODE_CBC, $iv);
        $encoded = base64_encode($passcrypt).'|'.base64_encode($iv);

        return $encoded;
    }

    /**
    |---------------------------
    | Decripts a key
    | @Params: key : string
    |
    |---------------------------
     */

    public static function decript($decrypt){
        #   Set the encription Key
        self::setKey();

        #   Get stuff out of it
        $decrypt = explode('|', $decrypt.'|');
        $decoded = base64_decode($decrypt[0]);
        $iv = base64_decode($decrypt[1]);

        if(strlen($iv)!==mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_CBC)){
            return false;
        }

        $key = pack('H*', static::$key64);
        $decrypted = trim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, $decoded, MCRYPT_MODE_CBC, $iv));
        $mac = substr($decrypted, -64);
        $decrypted = substr($decrypted, 0, -64);
        $calcmac = hash_hmac('sha256', $decrypted, substr(bin2hex($key), -32));
        if($calcmac!==$mac){
            return false;
        }
        $decrypted = unserialize($decrypted);
        return $decrypted;
    }

    /**
    |---------------------------
    | Hashed a key
    | @Params: key : string , method : string ( Default MCRYPT_BLOWFISH ) , $options : array
    | @Notes: Difference between encription and hash is that encription is a two way process,
    |   as it is made so the key can be achieved without guessing.
    |---------------------------
     */

    public static function hash($string, $method = false , $options = array()){
        if($method == false){
            $options = array(
                'cost'  =>  10
            );
            return password_hash($string, self::$mode, $options);
        }
        return password_hash($string, $method, $options);
    }

    /**
    |---------------------------
    | Compares a hash
    | @Params: key : string, hash : string
    |---------------------------
     */

    public static function compare($string, $hash ){
        return password_verify ( $string ,$hash );
    }


}