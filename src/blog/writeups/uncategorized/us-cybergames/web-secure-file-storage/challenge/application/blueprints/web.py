from flask import Blueprint, render_template, redirect, flash, current_app as app
from application.util import isAuthenticated
from application.database import list_user_files_db, fetch_file_db
import os

web = Blueprint('web', __name__)


@web.route('/', methods=['GET'])
def loginView():
    return render_template('login.html')


@web.route('/register', methods=['GET'])
def registerView():
    return render_template('register.html')

@web.route('/logout', methods=['GET'])
def logoutView():
    resp = redirect("/")
    resp.set_cookie("auth","")
    resp.set_cookie("session","")
    return resp


@web.route('/files', methods=['GET'])
@isAuthenticated
def fileView(user):

    user_files = list_user_files_db(user["id"])

    return render_template('files.html',
                           username=user["username"],
                           files=user_files)