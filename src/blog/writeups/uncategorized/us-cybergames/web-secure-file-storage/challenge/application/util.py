from flask import jsonify, request, flash, redirect, current_app as app
from functools import wraps
import jwt
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import logging

def response(message):
    return jsonify({'message': message})

def isAuthenticated(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.cookies.get('auth', False)
        if not token:
            logging.error("No token given: %s" % token)
            flash("You must be logged in to access this page.","danger")
            return redirect("/")
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'], algorithms=["HS256"])
            kwargs['user'] = data
            return f(*args, **kwargs)
        except Exception as e:
            logging.error(e)
            flash("You must be logged in to access this page.","danger")
            return redirect("/")
    return decorator

def encrypt(plaintext):
    try:
        
        if type(plaintext) == str:
            plaintext = plaintext.encode()

        cipher = AES.new(app.config["AES_KEY"], AES.MODE_CBC)
        enc = cipher.encrypt(pad(plaintext, AES.block_size))
        return base64.b64encode(cipher.iv+enc)
    except Exception as e:
        logging.error(e)
        return None

def decrypt(ciphertext):
    try:
        ciphertext = base64.b64decode(ciphertext)
        iv,ciphertext = ciphertext[:16],ciphertext[16:]
        cipher = AES.new(app.config["AES_KEY"], AES.MODE_CBC,iv=iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    except Exception as e:
        logging.error(e)
        return None
    
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]