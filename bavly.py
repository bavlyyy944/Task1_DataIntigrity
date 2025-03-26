import os
from flask import Flask, request, jsonify, make_response
import pymysql
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import base64
from functools import wraps

app = Flask(__name__)

# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Set your MySQL password here
app.config['MYSQL_DB'] = 'secure_flask_api'
app.config['SECRET_KEY'] = 'your-very-secret-key-123'  # Change this for production!

def get_db_connection(create_db=False):
    if create_db:
        # Connect without specifying a database to create it
        return pymysql.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            cursorclass=pymysql.cursors.DictCursor
        )
    else:
        # Normal connection with database specified
        return pymysql.connect(
            host=app.config['MYSQL_HOST'],
            user=app.config['MYSQL_USER'],
            password=app.config['MYSQL_PASSWORD'],
            database=app.config['MYSQL_DB'],
            cursorclass=pymysql.cursors.DictCursor
        )

# Initialize database
def init_db():
    try:
        # First, try to connect to the database
        connection = get_db_connection()
        connection.close()
        print("Database exists, proceeding...")
    except pymysql.err.OperationalError as e:
        if e.args[0] == 1049:  # Unknown database error
            try:
                print("Database doesn't exist, creating it...")
                admin_conn = get_db_connection(create_db=True)
                with admin_conn.cursor() as cursor:
                    cursor.execute(f"CREATE DATABASE IF NOT EXISTS {app.config['MYSQL_DB']}")
                    cursor.execute(f"USE {app.config['MYSQL_DB']}")
                    
                    # Create Users table
                    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS Users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        password VARCHAR(256) NOT NULL,
                        secret_key VARCHAR(50) NOT NULL
                    )
                    """)
                    
                    # Create Products table
                    cursor.execute("""
                    CREATE TABLE IF NOT EXISTS Products (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        name VARCHAR(100) NOT NULL,
                        description VARCHAR(255),
                        price DECIMAL(10,2) NOT NULL,
                        quantity INT NOT NULL
                    )
                    """)
                admin_conn.commit()
                print("Database and tables created successfully!")
            except Exception as create_error:
                print(f"Failed to create database: {create_error}")
                raise
            finally:
                if 'admin_conn' in locals():
                    admin_conn.close()
        else:
            print(f"Database connection failed: {e}")
            raise
    except Exception as e:
        print(f"Database initialization failed: {e}")
        raise

# Initialize the database
try:
    init_db()
except Exception as e:
    print(f"Application startup failed: {e}")
    exit(1)

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            connection = get_db_connection()
            with connection.cursor() as cursor:
                cursor.execute("SELECT * FROM Users WHERE username = %s", (data['username'],))
                current_user = cursor.fetchone()
            connection.close()
        except Exception as e:
            return jsonify({'message': 'Token is invalid!', 'error': str(e)}), 401
            
        return f(current_user, *args, **kwargs)
        
    return decorated

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 400
    
    username = data['username']
    password = data['password']
    
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            # Check if user already exists
            cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if user:
                return jsonify({'message': 'User already exists!'}), 400
            
            # Generate secret key for 2FA
            secret_key = pyotp.random_base32()
            
            # Hash password with correct method
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            
            # Insert new user
            cursor.execute(
                "INSERT INTO Users (username, password, secret_key) VALUES (%s, %s, %s)",
                (username, hashed_password, secret_key)
            )
            connection.commit()
            
        return jsonify({
            'message': 'User registered successfully!',
            'secret_key': secret_key,
            'instructions': 'Use the /get-qr endpoint to get a QR code for 2FA setup'
        }), 201
    except Exception as e:
        return jsonify({'message': 'Registration failed!', 'error': str(e)}), 500
    finally:
        connection.close()

# Get QR Code for 2FA setup
@app.route('/get-qr', methods=['GET'])
def get_qr():
    username = request.args.get('username')
    
    if not username:
        return jsonify({'message': 'Username is required as a query parameter!'}), 400
    
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT secret_key FROM Users WHERE username = %s", (username,))
            result = cursor.fetchone()
            
            if not result:
                return jsonify({'message': 'User not found!'}), 404
            
            secret_key = result['secret_key']
            
            # Create TOTP URI
            totp = pyotp.totp.TOTP(secret_key)
            totp_uri = totp.provisioning_uri(name=username, issuer_name="Flask Auth API")
            
            # Generate QR Code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(totp_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            buffer = BytesIO()
            img.save(buffer, format="PNG")
            qr_base64 = base64.b64encode(buffer.getvalue()).decode('ascii')
            
            return jsonify({
                'qr_code': f"data:image/png;base64,{qr_base64}",
                'secret_key': secret_key,
                'message': 'Scan this QR code with Google Authenticator'
            })
    except Exception as e:
        return jsonify({'message': 'Failed to generate QR code!', 'error': str(e)}), 500
    finally:
        connection.close()

# Login with 2FA verification
@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 400
    
    username = auth['username']
    password = auth['password']
    
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM Users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if not user:
                return jsonify({'message': 'User not found!'}), 404
            
            if check_password_hash(user['password'], password):
                # Password is correct, now check for 2FA code
                if not auth.get('totp_code'):
                    return jsonify({
                        'message': '2FA code is required!',
                        'hint': 'Get the code from your authenticator app'
                    }), 401
                
                secret_key = user['secret_key']
                totp = pyotp.totp.TOTP(secret_key)
                
                if not totp.verify(auth['totp_code'], valid_window=1):
                    return jsonify({'message': 'Invalid 2FA code!'}), 401
                
                # Generate JWT token
                token = jwt.encode({
                    'username': username,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
                }, app.config['SECRET_KEY'], algorithm="HS256")
                
                return jsonify({
                    'token': token,
                    'message': 'Login successful!',
                    'expires_in': '10 minutes'
                })
            
            return jsonify({'message': 'Invalid credentials!'}), 401
    except Exception as e:
        return jsonify({'message': 'Login failed!', 'error': str(e)}), 500
    finally:
        connection.close()

# Product CRUD Operations

# Create Product
@app.route('/products', methods=['POST'])
@token_required
def create_product(current_user):
    data = request.get_json()
    
    required_fields = ['name', 'price', 'quantity']
    if not data or not all(field in data for field in required_fields):
        return jsonify({
            'message': 'Missing required fields!',
            'required_fields': required_fields
        }), 400
    
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("""
                INSERT INTO Products (name, description, price, quantity) 
                VALUES (%s, %s, %s, %s)
            """, (
                data['name'],
                data.get('description', ''),
                data['price'],
                data['quantity']
            ))
            product_id = cursor.lastrowid
            connection.commit()
            
            return jsonify({
                'message': 'Product created successfully!',
                'product_id': product_id
            }), 201
    except Exception as e:
        return jsonify({'message': 'Failed to create product!', 'error': str(e)}), 500
    finally:
        connection.close()

# Get All Products
@app.route('/products', methods=['GET'])
@token_required
def get_all_products(current_user):
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM Products")
            products = cursor.fetchall()
            
            output = []
            for product in products:
                product_data = {
                    'id': product['id'],
                    'name': product['name'],
                    'description': product['description'],
                    'price': float(product['price']),
                    'quantity': product['quantity']
                }
                output.append(product_data)
            
            return jsonify({
                'count': len(output),
                'products': output
            })
    except Exception as e:
        return jsonify({'message': 'Failed to fetch products!', 'error': str(e)}), 500
    finally:
        connection.close()

# Get Single Product
@app.route('/products/<int:product_id>', methods=['GET'])
@token_required
def get_product(current_user, product_id):
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM Products WHERE id = %s", (product_id,))
            product = cursor.fetchone()
            
            if not product:
                return jsonify({'message': 'Product not found!'}), 404
            
            product_data = {
                'id': product['id'],
                'name': product['name'],
                'description': product['description'],
                'price': float(product['price']),
                'quantity': product['quantity']
            }
            
            return jsonify(product_data)
    except Exception as e:
        return jsonify({'message': 'Failed to fetch product!', 'error': str(e)}), 500
    finally:
        connection.close()

# Update Product
@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    data = request.get_json()
    
    if not data:
        return jsonify({'message': 'No data provided for update!'}), 400
    
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM Products WHERE id = %s", (product_id,))
            product = cursor.fetchone()
            
            if not product:
                return jsonify({'message': 'Product not found!'}), 404
            
            # Get existing values if not provided in update
            name = data.get('name', product['name'])
            description = data.get('description', product['description'])
            price = data.get('price', product['price'])
            quantity = data.get('quantity', product['quantity'])
            
            cursor.execute("""
                UPDATE Products 
                SET name = %s, description = %s, price = %s, quantity = %s
                WHERE id = %s
            """, (name, description, price, quantity, product_id))
            
            connection.commit()
            
            return jsonify({'message': 'Product updated successfully!'})
    except Exception as e:
        return jsonify({'message': 'Failed to update product!', 'error': str(e)}), 500
    finally:
        connection.close()

# Delete Product
@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT * FROM Products WHERE id = %s", (product_id,))
            product = cursor.fetchone()
            
            if not product:
                return jsonify({'message': 'Product not found!'}), 404
            
            cursor.execute("DELETE FROM Products WHERE id = %s", (product_id,))
            connection.commit()
            
            return jsonify({'message': 'Product deleted successfully!'})
    except Exception as e:
        return jsonify({'message': 'Failed to delete product!', 'error': str(e)}), 500
    finally:
        connection.close()

# Health check endpoint
@app.route('/health', methods=['GET'])
def health_check():
    try:
        connection = get_db_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        return jsonify({
            'status': 'healthy',
            'database': 'connected'
        })
    except Exception as e:
        return jsonify({
            'status': 'healthy',
            'database': 'disconnected',
            'error': str(e)
        }), 500
    finally:
        connection.close()

if __name__ == '__main__':
    app.run(debug=True)
