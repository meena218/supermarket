import os
import json
from flask import Flask, render_template, request, redirect, session, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from io import BytesIO
from flask_migrate import Migrate
from functools import wraps


db = SQLAlchemy()
migrate = Migrate()

active_admins = set()  # This will track active admin sessions

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sp.db'
    app.config["SECRET_KEY"] = "Meena"

    db.init_app(app)
    migrate.init_app(app, db)
    
    with app.app_context():
        db.create_all()

    return app

# Product model with BLOB storage for image
class Product(db.Model):
    __tablename__ = 'product'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(200), nullable=False)
    image_data = db.Column(db.LargeBinary, nullable=False)  # Storing images as BLOB
    category = db.Column(db.String(100), nullable=False)

# User model
class User(db.Model):
    __tablename__ = 'users'
    username = db.Column(db.String(100), nullable=False, primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    pw = db.Column(db.String(100), nullable=False)
    secPw = db.Column(db.String(100), nullable=False)

# Admin model
class Admin(db.Model):
    __tablename__ = 'admins'
    username = db.Column(db.String(100), nullable=False, primary_key=True)
    password = db.Column(db.String(100), nullable=False)

app = create_app()

'''
def create_admins():
    # Check if the admin users already exist to prevent duplicates
    if Admin.query.count() == 0:  # Only add admins if the table is empty
        admin1 = Admin(username='admin1', password=generate_password_hash('password1'))
        admin2 = Admin(username='admin2', password=generate_password_hash('password2'))
        admin3 = Admin(username='admin3', password=generate_password_hash('password3'))
        #admin4 = Admin(username='admin4', password=generate_password_hash('password4'))  

        db.session.add(admin1)
        db.session.add(admin2)
        db.session.add(admin3)
       # db.session.add(admin4) 
        db.session.commit()
        print("Admin users created successfully.")
    else:
        print("Admin users already exist.")
'''

def load_products_from_json(json_file):
    with open(json_file, 'r') as file:
        products_data = json.load(file)
    for product in products_data:
        name = product['name']
        price = product['price']
        description = product['description']
        category = product['category']
        image_path = product['image_path']  # Get the image path from JSON
        
        # Load the image as binary data
        with open(image_path, "rb") as image_file:
            image_data = image_file.read()

        new_product = Product(
            name=name,
            price=price,
            description=description,
            image_data=image_data,
            category=category
        )
        db.session.add(new_product)
    
    db.session.commit()  # Commit once after all products are added


# Route to serve images directly as binary data
@app.route('/product_image/<int:product_id>')
def product_image(product_id):
    product = Product.query.get(product_id)
    if product:
        return send_file(BytesIO(product.image_data), mimetype='image/png')
    return "Image not found", 404

# Signup route
@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        pw = request.form.get('pw')
        users = User(username=username, email=email, pw=pw, secPw=pw)
        db.session.add(users)
        db.session.commit()
        return redirect('/home')
    return render_template('signup.html')

# Login route
@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        pw = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.pw == pw:  # Add password check
            session['username'] = username
            session["islogin"] = True
            return redirect('/home')
        else:
            return render_template('login.html', error="Invalid Username and Password")
    return render_template('login.html')

# Admin Login
@app.route('/admin_login', methods=['POST', 'GET'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check for admin credentials
        admin = Admin.query.filter_by(username=username).first()
        
        if admin and check_password_hash(admin.password, password):
            if len(active_admins) < 4:  # Check if there are fewer than 4 active sessions
                session['admin_username'] = username
                active_admins.add(username)  # Add to active sessions
                return redirect('/admin_dashboard')
            else:
                return render_template('admin_login.html', error="Maximum number of admins logged in. Try again later.")
        else:
            return render_template('admin_login.html', error="Invalid Username or Password")
    return render_template('admin_login.html')

def alogin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print("Current session:", session)  # Debugging line
        if 'admin_username' not in session:  # Check if the admin is logged in
            return redirect(url_for('admin_login'))  # Redirect to admin login if not logged in
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin_dashboard', methods=['GET'])
@alogin_required  # Protect the admin dashboard route
def admin_dashboard():
    if 'admin_username' not in session:
        return redirect('/admin_login')
    return render_template('admin_dashboard.html')

# Route for product upload (manually add product and image)
@app.route('/upload_product', methods=['POST', 'GET'])
@alogin_required  # Protect the admin dashboard route
def upload_product():
    if request.method == 'POST':
        name = request.form.get('name')
        price = float(request.form.get('price'))
        description = request.form.get('description')
        category = request.form.get('category')

        if 'image' not in request.files:
            return redirect('/upload_product')

        file = request.files['image']
        image_data = file.read()  # Read file as binary for BLOB storage

        new_product = Product(name=name, price=price, description=description, image_data=image_data, category=category)
        db.session.add(new_product)
        db.session.commit()

        return redirect('/admin_dashboard')

    return render_template('upload_product.html')

@app.route('/load_products', methods=['POST', 'GET'])
@alogin_required  # Protect the admin dashboard route
def load_products():
    if request.method == 'POST':
        json_file = request.files['json_file']
        json_file.save(secure_filename(json_file.filename))
        load_products_from_json(json_file.filename)
        return redirect('/admin_dashboard')
    return render_template('load_products.html')

# Home route displaying products
@app.route('/home')
def home():
    vegetables = Product.query.filter_by(category='vegetable').all()
    fruits = Product.query.filter_by(category='fruit').all()
    dairy = Product.query.filter_by(category='dairy').all()
    return render_template('home.html', vegetables=vegetables, fruits=fruits, dairy=dairy)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'islogin' not in session:  # Check if the user is logged in
            return redirect(url_for('login'))  # Redirect to login if not logged in
        return f(*args, **kwargs)
    return decorated_function


# Cart route
@app.route('/cart')
@login_required  # Protect the cart route
def cart():
    cart_items = session.get('cart', [])
    total = sum([item['price'] for item in cart_items])
    return render_template('cart.html', cart=cart_items, total=total)

# Add to cart
@app.route('/add_to_cart', methods=['POST'])
def add_to_cart():
    product_name = request.form.get('product_name')
    product = Product.query.filter_by(name=product_name).first()
    cart = session.get('cart', [])
    cart.append({'name': product.name, 'price': product.price})
    session['cart'] = cart
    return redirect('/cart')

# Remove from cart
@app.route('/remove_from_cart', methods=['POST'])
def remove_from_cart():
    product_name = request.form.get('product_name')
    cart = session.get('cart', [])
    session['cart'] = [item for item in cart if item['name'] != product_name]
    return redirect('/cart')

# Contact route
@app.route('/contact', methods=['GET', 'POST'])
@login_required  # Protect the cart route
def contact():
    if request.method == 'POST':
        return redirect('/home')
    return render_template('contact.html')

# User Logout route
@app.route('/logout')
def logout():
    session.clear()
    return redirect('login')

# Admin Logout route
@app.route('/admin_logout')
def admin_logout():
    # Check if an admin is logged in
    if 'admin_username' in session:
        active_admins.discard(session.get('admin_username'))  # Remove from active sessions for admins

    # Clear the session
    session.clear()
    
    return redirect('/admin_login')  # Redirect to login page



if __name__ == '__main__':
    with app.app_context():
        #create_admins()  # Call the function to create admins
        #db.drop_all()
        #db.create_all()  # Ensure all tables are created
        app.run(debug=True)
