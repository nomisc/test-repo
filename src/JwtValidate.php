<?php


namespace Pirnar\JwtAuth;


class JwtValidate
{
    const _jwtAccessTokenName = '_pirnarJwtAcc';

    const _jwtRefreshTokenName = '_pirnarJwtRfr';

    const _authServer = 'https://auth-dev.pirnar.io/';

    const _validateRequest = '/validate';

    const _refreshRequest = '/refresh';

    private $_jwtRefreshToken;

    private $_jwtAccessToken;

    private function CurlCall($token,$command) {

        $data = json_encode(array('token'=>$token));

        $curl = curl_init();

        curl_setopt_array($curl, array(
            CURLOPT_URL => self::_authServer.$command,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 0,
            CURLOPT_CUSTOMREQUEST => "POST",
            CURLOPT_POSTFIELDS => $data,
            CURLOPT_HTTPHEADER => array(
                "Content-Type: application/json"
            ),
        ));
        $response = curl_exec($curl);
        curl_close($curl);
        return $response;
    }

    public function SetAccessToken() {
        $this->_jwtAccessToken = $_COOKIE[self::_jwtAccessTokenName];
    }

    public function SetRefreshToken() {
        $this->_jwtRefreshToken = $_COOKIE[self::_jwtRefreshTokenName];
    }

    public function ValidateRefreshToken() {
        $rsp = $this->CurlCall($this->_jwtRefreshToken,self::_validateRequest);
        var_dump(json_decode($rsp));
    }
}