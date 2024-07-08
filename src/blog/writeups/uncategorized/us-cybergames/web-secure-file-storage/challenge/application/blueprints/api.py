from application.database import register_user_db, login_user_db, list_user_files_db, insert_file_db, fetch_file_db, delete_file_db
from flask import Blueprint, request, redirect, flash, current_app as app, send_file
from application.util import isAuthenticated, response, allowed_file, encrypt, decrypt
from werkzeug.utils import secure_filename
import os

api = Blueprint('api', __name__)

@api.route('/auth/login', methods=['POST'])
def api_login():

    username = request.form.get('username', '').lower()
    password = request.form.get('password', '')

    if not username or not password:
        flash("All fields are required.","danger")
        return redirect("/")

    token = login_user_db(username, password)

    if token:
        flash("Logged In successfully!","success")
        res = redirect("/files")
        res.set_cookie('auth', token)

        return res

    flash('Invalid credentials.',"danger")
    return redirect("/")


@api.route('/auth/register', methods=['POST'])
def api_register():

    username = request.form.get('username', '').lower()
    password = request.form.get('password', '')

    if not username or not password:
        flash("All fields are required.","danger")
        return redirect("/register")
    
    if any([u not in app.config["ALLOWED_USER_CHARS"] for u in username]):
        flash("Illegal characters in username.","danger")
        return redirect("/register")

    user = register_user_db(username, password)

    if user:

        user_folder = os.path.join(app.config['UPLOAD_FOLDER'], username)

        if not os.path.exists(user_folder):
            os.makedirs(user_folder)

        flash("User registered, please log in.","success")
        return redirect("/")

    flash('User already exists!',"danger")
    return redirect("/register")

@api.route('/files/upload', methods=['POST'])
@isAuthenticated
def upload_file(user):

    file = request.files.get("file")
    title = request.form.get("title")

    if not file or file.filename == "":
        flash('You must select a file to upload.',"danger")
        return redirect("/files")
    
    if not title or title == "":
        flash('You must enter a title for your file.',"danger")
        return redirect("/files")
    
    if not allowed_file(file.filename):
        flash(f'The following filetypes are allowed: [{",".join(app.config["ALLOWED_EXTENSIONS"])}]',"danger")
        return redirect("/files")
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'],user["username"])
    file.save(os.path.join(filepath,filename))

    insert_file_db(user["id"],filepath,filename,title)

    flash('File uploaded successfully!',"success")
    return redirect("/files")


@api.route('/files/download/<file_id>', methods=['GET'])
@api.route('/files/download', methods=["POST"], defaults={"file_id":None})
@isAuthenticated
def download_file(file_id,user):

    if not file_id:
        file_id = request.form.get("file_id")

    if not file_id:
        flash('No file ID provided.',"danger")
        return redirect("/files")
    
    file = fetch_file_db(user["id"],file_id)

    if not file:
        flash('Invalid file provided, or you may not have permission to view this file.',"danger")
        return redirect("/files")
    
    return send_file(os.path.join(file["filepath"],file["filename"]), as_attachment=True, download_name=file["filename"])

@api.route('/files/delete/<file_id>', methods=['GET'])
@isAuthenticated
def delete_file(file_id,user):

    if not file_id:
        flash('No file ID provided.',"danger")
        return redirect("/files")
    
    file = delete_file_db(user["id"],file_id)

    if not file:
        flash('Invalid file provided, or you may not have permission to view this file.',"danger")
        return redirect("/files")
    
    os.unlink(os.path.join(file["filepath"],file["filename"]))

    flash('File deleted successfully!',"success")
    return redirect("/files")

@api.route('/files/info', methods=['POST'])
@isAuthenticated
def file_info(user):

    file_id = request.form.get("file_id")

    if not file_id:
        return response({"error":'No file ID provided.'})
    
    file = fetch_file_db(user["id"],file_id)

    if not file:
        return response({"error":'Invalid file provided, or you may not have permission to view this file.'})
    
    size = os.path.getsize(os.path.join(file["filepath"],file["filename"]))
    
    return response({"file":file,"size":size})





