from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request

secret_key = b"\x11" * 16
app = Flask(__name__)

@app.route('/')
def index():
    data = bytes.fromhex(request.args['data'])
    aes = AES.new(secret_key, AES.MODE_CBC, iv=data[:16])
    return bytes.hex(unpad(aes.decrypt(data[16:]), 16))

if __name__ == "__main__":
    app.run(debug=True)