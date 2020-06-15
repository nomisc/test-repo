<?php


namespace Pirnar\JwtAuth;


class JwtValidate
{

    private $_jwtRefreshToken;

    private $_jwtAccessToken;

    private $_loginServer;

    private $_cookieDomain;

    private $_accessTokenTime;

    private $_refreshTokenTime;

    private $_refreshTokenName;

    private $_accessTokenName;

    private $_validateRequest;

    private $_refreshRequest;

    private $_authServer;

    private $config;

    private $status;

    public function __construct()
        {
            $this->Config();
            $this->_loginServer = $this->config->_loginServer;
            $this->_cookieDomain =$this->config->_cookieDomain;
            $this->_accessTokenTime = $this->config->_accessTokenTime;
            $this->_refreshTokenTime = $this->config->_refreshTokenTime;
            $this->_refreshTokenName = $this->config->_jwtRefreshTokenName;
            $this->_accessTokenName = $this->config->_jwtAccessTokenName;
            $this->_validateRequest = $this->config->_validateRequest;
            $this->_refreshRequest = $this->config->_refreshRequest;
            $this->_authServer = $this->config->_authServer;

            $this->_jwtAccessToken =(isset( $_COOKIE[$this->_accessTokenName]) ? $_COOKIE[$this->_accessTokenName] : false) ;
            $this->_jwtRefreshToken =(isset( $_COOKIE[$this->_refreshTokenName]) ?  $_COOKIE[$this->_refreshTokenName] : false) ;

        }

    private function Config() {
        $configArray = array(
            "_jwtAccessTokenName" => "_pirnarJwtAcc",
            "_jwtRefreshTokenName"=>"_pirnarJwtRfr",
            "_authServer"=>"https=>//auth-dev.pirnar.io/",
            "_validateRequest"=>"/validate",
            "_refreshRequest"=>"/token",
            "_cookieDomain"=>".pirnar.si",
            "_accessTokenTime"=>"300",
            "_refreshTokenTime"=>"3600",
            "_loginServer"=>"https://login.pirnar.si/"
        );
        $config = json_decode(file_get_contents(__DIR__.'/config.json'), true);
        $this->config  = (object) array_merge($configArray, $config);
    }

    private function CurlCall($token,$command) {

            $data = json_encode(array('token'=>$token));

            $curl = curl_init();

            curl_setopt_array($curl, array(
                CURLOPT_URL => $this->_authServer.$command,
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

    private function SetAccessTokenCookie() {
        setcookie($this->_accessTokenName,$this->_jwtAccessToken,time()+$this->_accessTokenTime,"/",$this->_cookieDomain,false,true);
    }

    private function SetRefreshTokenCookie() {
        setcookie($this->_refreshTokenName,$this->_jwtRefreshToken,time()+$this->_refreshTokenTime,"/",$this->_cookieDomain,false,true);
    }

    private function UnsetAccessTokenCookie() {
        setcookie($this->_accessTokenName,$this->_jwtAccessToken,time()-3600,"/",$this->_cookieDomain,false,true);
    }

    private function UnsetRefreshTokenCookie() {
        setcookie($this->_refreshTokenName,$this->_jwtRefreshToken,time()-3600,"/",$this->_cookieDomain,false,true);
    }

    public function TokenValidation($redirect = true) {
        $responseAccess = json_decode($this->CurlCall($this->_jwtAccessToken,$this->_validateRequest));
        if ($responseAccess->StatusCode !== 200) {
            $responseRefresh = json_decode($this->CurlCall($this->_jwtRefreshToken,$this->_refreshRequest));
            $this->status =  $responseRefresh;
            if ($responseRefresh->StatusCode === 200) {
                $this->_jwtAccessToken = $responseRefresh->AccessToken;
                $this->_jwtRefreshToken = $responseRefresh->RefreshToken;
                $this->SetAccessTokenCookie();
                $this->SetRefreshTokenCookie();
            }
            else {
                if ($redirect) {
                    header("Location: ". $this->_loginServer);
                }
                $this->status = $responseRefresh;
            }
        }
        else {
            $this->status = $responseAccess;
        }
    }

    public function GetStatus() {
        return $this->status;
    }

    public static function  SecureCheck() {
        $class = new JwtValidate();
        $class->TokenValidation();
        return $class->GetStatus();
    }

    public static function Logout() {
        $class = new JwtValidate();
        $class->UnsetAccessTokenCookie();
        $class->UnsetRefreshTokenCookie();
    }
}