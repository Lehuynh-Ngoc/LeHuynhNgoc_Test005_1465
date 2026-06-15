from flask import Flask, request, jsonify
from cipher.ecc import ECCCipher

app = Flask(__name__)

# RSA CIPHER ALGORITHM


# ECC CIPHER ALGORITHM
ecc_cipher = ECCCipher()


# ECC CIPHER ALGORITHM
@app.route('/api/ecc/generate_keys', methods=['GET'])
def ecc_generate_keys():
    ecc_cipher.generate_keys()
    return jsonify({'message': 'ECC Keys generated successfully'})

@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign_message():
    data = request.json
    message = data['message']
    sk, _ = ecc_cipher.load_keys()
    signature = ecc_cipher.sign(message, sk)
    signature_hex = signature.hex()
    return jsonify({'signature': signature_hex})

@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify_signature():
    data = request.json
    message = data['message']
    signature_hex = data['signature']
    _, vk = ecc_cipher.load_keys()
    signature = bytes.fromhex(signature_hex)
    is_verified = ecc_cipher.verify(message, signature, vk)
    return jsonify({'is_verified': is_verified})

# main function
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
