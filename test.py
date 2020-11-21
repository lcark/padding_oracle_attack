from padding_oracle_attack import payload_model
import grequests
from grequests import request

class payload(payload_model):

    def make_request(self, fake_data) -> request:
        params = {
                "data": bytes.hex(fake_data)
            }

        return request("get", "http://127.0.0.1:5000", params=params)

if __name__ == "__main__":
    m = payload("3a10f84900818b1c439430600524fb0f00000000000000000000000000000000")
    m.run()