from flask import Flask, jsonify, request, session, flash, make_response,sessions
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS #pip install -U flask-cors
from datetime import timedelta
from psycopg2 import connect, extras
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash

import os
import psycopg2 #pip install psycopg2 
import psycopg2.extras
import logging

load_dotenv()

logging.basicConfig (level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

app = Flask(__name__)
url = os.getenv("DATABASE_URL")
connection = psycopg2.connect(url)

app.config['SECRET_KEY'] = 'cairocoders-ednalan'


DB_HOST = "localhost"
DB_NAME = "sampledb2"
DB_USER = "postgres"
DB_PASS = "admin"

conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST)

CREATE_USERS_TABLE = "CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT);"

with connection:
    with connection.cursor() as cursor:
        cursor.execute(CREATE_USERS_TABLE)
        
def is_user_logged_in(username):
    return 'username' in session and session['username'] == username

def is_any_user_logged_in():
    return 'username' in session

@app.route('/')
def home():
    logging.info('Berhasil')
    passhash = generate_password_hash('unsia')
    print(passhash)
    if 'username' in session:
        username = session['username']
        return jsonify({'message' : 'Kamu Saat Ini Login Menggunakan', 'username' : username})
    else:
        resp = jsonify({'message' : 'Unauthorized'})
        resp.status_code = 401
        return resp
  
@app.route('/login', methods=['POST'])
def login():
    logging.info('Berhasil')
    _json = request.json
    _username = _json['username']
    _password = _json['password']
    print(_password)
    if _username and _password:
        # Check user exists          
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
          
        sql = "SELECT * FROM useraccount WHERE username=%s"
        sql_where = (_username,)
          
        cursor.execute(sql, sql_where)
        row = cursor.fetchone()
        
        if row:
            username = row['username']
            password = row['password']
            
            if check_password_hash(password, _password):
                if is_any_user_logged_in():
                    # Jika ada pengguna lain yang sudah masuk, beri respons bahwa hanya satu akun yang dapat login pada suatu waktu
                    resp = jsonify({'message': 'Hanya satu akun yang dapat login pada satu waktu'})
                    resp.status_code = 400
                    return resp
                
                session['username'] = username
                cursor.close()
                return jsonify({'message' : 'Kamu Berhasil Login'})
            else:
                resp = jsonify({'message' : 'Bad Request - invalid password'})
                resp.status_code = 400
                return resp
    else:
        resp = jsonify({'message' : 'Bad Request - invalid credentials'})
        resp.status_code = 400
        return resp
    
INSERT_USER_RETURN_ID = "INSERT INTO useraccount (username, password) VALUES (%s, %s) RETURNING id;"
@app.route("/api/user", methods=["POST"])
def create_user():
    logging.info('Berhasil')
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    
    passhash = generate_password_hash(password)
    
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(INSERT_USER_RETURN_ID, (username, passhash))
            user_id = cursor.fetchone()[0]
    return {"id": user_id, "name": username, "message": f"User {username} Berhasil dibuat."}, 201

SELECT_ALL_USERS = "SELECT * FROM useraccount;"
@app.route("/api/user", methods=["GET"])
def get_all_users():
    logging.info('Berhasil')
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(SELECT_ALL_USERS)
            users = cursor.fetchall()
            if users:
                result = []
                for user in users:
                    result.append({"id": user[0], "name": user[1]})
                return jsonify(result)
            else:
                return jsonify({"error": f"Users not found."}), 404

@app.route("/api/user/<int:user_id>", methods=["GET"])
def get_user(user_id):
    logging.info('Berhasil')
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM useraccount WHERE id = %s", (user_id,)) 
            user = cursor.fetchone()
            if user:
                return jsonify({"id": user[0], "name": user[1]})
            else:
                return jsonify({"error": f"User with ID {user_id} not found."}), 404 
            
UPDATE_USER_BY_ID = "UPDATE useraccount SET username = %s, password = %sWHERE id = %s;"
@app.route("/api/user/<int:user_id>", methods=["PUT"])
def update_user(user_id):
    logging.info('Berhasil')
    data = request.get_json()
    username = data["username"]
    password = data["password"]
    
    passhash = generate_password_hash(password)
    
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(UPDATE_USER_BY_ID, (username, passhash, user_id))
            if cursor.rowcount == 0:
                return jsonify({"error": f"User with ID {user_id} not found."}), 404
    return jsonify({"id": user_id, "password": passhash,"name": username, "message": f"User with ID {user_id} updated."})

DELETE_USER_BY_ID = "DELETE FROM useraccount WHERE id = %s;"
@app.route("/api/user/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):
    logging.info('Berhasil')
    with connection:
        with connection.cursor() as cursor:
            cursor.execute(DELETE_USER_BY_ID, (user_id,))
            if cursor.rowcount == 0:
                return jsonify({"error": f"User with ID {user_id} not found."}), 404
    return jsonify({"message": f"User with ID {user_id} deleted."})
            
@app.route('/logout')
def logout():
    logging.info('Berhasil')
    if 'username' in session:
        session.pop('username', None)
    return jsonify({'message' : 'Kamu berhasil Keluar'})

if __name__ == "__main__":
    app.run()
