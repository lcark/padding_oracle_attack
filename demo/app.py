from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flask import Flask, request
from base64 import b64decode
from Crypto.Random import get_random_bytes

secret_key = get_random_bytes(AES.block_size)
app = Flask(__name__)

@app.route('/fuck')
def fuck():
    data = b64decode(request.cookies['id'].encode())
    aes = AES.new(secret_key, AES.MODE_CBC, iv=data[:16])
    id = unpad(aes.decrypt(data[16:]), 16).decode("latin1")
    return f"Hello {id} !!"

@app.route('/index')
@app.route('/')
def index():
    data = "bitch"
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    b = iv + cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return bytes.hex(b)

if __name__ == "__main__":
    app.run()