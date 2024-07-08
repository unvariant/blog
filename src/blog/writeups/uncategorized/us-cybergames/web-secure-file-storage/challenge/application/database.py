from flask import current_app as app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from application.util import decrypt, encrypt
import logging

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    title = db.Column(db.String(256), nullable=False)
    filename = db.Column(db.String(256), nullable=False)
    filepath = db.Column(db.String(256), nullable=False)

def login_user_db(username, password):

    user = User.query.filter_by(username=username).first()

    if not user:
        return False
    
    if check_password_hash(user.password, password):
        return jwt.encode({'username': user.username, 'id':user.id}, app.config['SECRET_KEY'], algorithm="HS256")
    
    return False

def register_user_db(username, password):

    # Check if username exists
    check_user = User.query.filter_by(username=username.lower()).first()

    # If not
    if not check_user:

        # Add new user to DB
        hashed_password = generate_password_hash(password)
        new_user = User(username=username.lower(), password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return True

    return False

def list_user_files_db(user_id):
    files = File.query.filter_by(user_id=user_id).all()
    results = []
    for file in files:
        file.filepath = decrypt(file.filepath).decode()
        file.filename = decrypt(file.filename).decode()
        if file.filename is not None and file.filepath is not None:
            results.append(file)
    return results

def insert_file_db(user_id,filepath,filename,title):

    new_file = File(user_id=user_id,
                    filepath=encrypt(filepath).decode(),
                    filename=encrypt(filename).decode(),
                    title=title)
    
    db.session.add(new_file)
    db.session.commit()
    return True

def delete_file_db(user_id,file_id):
    file = File.query.filter_by(id=file_id, user_id=user_id).first()
    if file:
        filepath = decrypt(file.filepath)
        filename = decrypt(file.filename)
        if file.user_id == user_id and filepath is not None and filename is not None:
            db.session.delete(file)
            db.session.commit()
            return {"id":file.id,"filepath":filepath.decode(),"filename":filename.decode(),"title":file.title}
        return False
    return False

def fetch_file_db(user_id,file_id):
    try:
        file = db.session.execute(text(f"SELECT * FROM File WHERE id = {file_id}")).first()
        if file:
            filepath = decrypt(file.filepath)
            filename = decrypt(file.filename)
            if file.user_id == user_id and filepath is not None and filename is not None:
                return {"id":file.id,"filepath":filepath.decode(),"filename":filename.decode(),"title":file.title}
        return False
    except Exception as e:
        logging.error(e)
        return False