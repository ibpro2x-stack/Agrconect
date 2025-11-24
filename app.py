import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_migrate import Migrate  # <-- Flask-Migrate

# --------------------------
# App & Config
# --------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'agrconet.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Uploads folder
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXT = {'png','jpg','jpeg','gif'}

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # <-- setup Flask-Migrate

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --------------------------
# Models
# --------------------------
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'seller' | 'customer' | 'admin'
    profile_pic = db.Column(db.String(300), default='default.png')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # <-- added

    products = db.relationship('Product', backref='seller', lazy=True)
    comments = db.relationship('Comment', backref='user', lazy=True)
    messages_sent = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    messages_received = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)

    def set_password(self, pw):
        self.password = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password, pw)


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price_rwf = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(300), default='default.png')
    seller_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    comments = db.relationship('Comment', backref='product', lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# --------------------------
# Create DB & admin (first-run)
# --------------------------
@app.before_request
def ensure_db():
    if not hasattr(app, 'db_ready'):
        db.create_all()
        admin_email = "ibpro2x@gmail.com"
        admin = User.query.filter_by(email=admin_email).first()
        if not admin:
            admin = User(username="Agrconect Administrator", email=admin_email, role="admin")
            admin.set_password("agrconect.admin")
            db.session.add(admin)
            db.session.commit()
        app.db_ready = True


# --------------------------
# Helpers
# --------------------------
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --------------------------
# Routes
# --------------------------
@app.route('/')
def index():
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('index.html', products=products)


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role', 'customer')
        if not username or not email or not password:
            flash("Please fill all required fields", "warning")
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash("Email already used", "warning")
            return redirect(url_for('register'))

        filename = 'default.png'
        file = request.files.get('profile_pic')
        if file and file.filename and allowed_file(file.filename):
            fn = secure_filename(file.filename)
            timestamped = f"{int(datetime.utcnow().timestamp())}_{fn}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], timestamped))
            filename = timestamped

        user = User(username=username, email=email, role=role, profile_pic=filename)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully, please login", "success")
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        id_or_email = request.form.get('email').strip()
        password = request.form.get('password')
        user = User.query.filter((User.email==id_or_email)|(User.username==id_or_email)).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        if id_or_email == "Agrconect Administrator" and password == "agrconet.admin":
            admin = User.query.filter_by(email="ibpro2x@gmail.com").first()
            if admin:
                login_user(admin)
                return redirect(url_for('dashboard'))
        flash("Invalid credentials", "danger")
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    products = Product.query.order_by(Product.created_at.desc()).all()
    if current_user.role == 'seller':
        return render_template('seller_dashboard.html', products=products)
    if current_user.role == 'customer':
        return render_template('customer_dashboard.html', products=products)
    if current_user.role == 'admin':
        users = User.query.order_by(User.created_at.desc()).all()
        return render_template('admin_dashboard.html', users=users, products=products)
    return abort(403)


@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if current_user.role != 'seller':
        flash("Only sellers can upload products", "warning")
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        price = request.form.get('price', '0')
        try:
            price = int(float(price))
        except:
            price = 0
        filename = 'default.png'
        file = request.files.get('image')
        if file and file.filename and allowed_file(file.filename):
            fn = secure_filename(file.filename)
            timestamped = f"{int(datetime.utcnow().timestamp())}_{fn}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], timestamped))
            filename = timestamped

        p = Product(title=title, description=description, price_rwf=price, image=filename, seller_id=current_user.id)
        db.session.add(p)
        db.session.commit()
        flash("Product uploaded", "success")
        return redirect(url_for('dashboard'))
    return render_template('upload.html')


@app.route('/product/<int:pid>', methods=['GET'])
def product_detail(pid):
    p = Product.query.get_or_404(pid)
    return render_template('product_detail.html', product=p)


@app.route('/comment/<int:pid>', methods=['POST'])
@login_required
def comment(pid):
    text = request.form.get('text', '').strip()
    if not text:
        flash("Comment empty", "warning")
        return redirect(url_for('product_detail', pid=pid))
    c = Comment(text=text, user_id=current_user.id, product_id=pid)
    db.session.add(c)
    db.session.commit()
    flash("Comment posted", "success")
    return redirect(url_for('product_detail', pid=pid))


@app.route('/message/send/<int:receiver_id>/<int:product_id>', methods=['POST'])
@login_required
def send_message(receiver_id, product_id):
    text = request.form.get('text', '').strip()
    if not text:
        flash("Message empty", "warning")
        return redirect(url_for('dashboard'))
    recv = User.query.get(receiver_id)
    if not recv:
        flash("Recipient not found", "danger")
        return redirect(url_for('dashboard'))
    msg = Message(text=text, sender_id=current_user.id, receiver_id=receiver_id, product_id=product_id)
    db.session.add(msg)
    db.session.commit()
    flash("Message sent", "success")
    return redirect(url_for('conversation', partner_id=receiver_id))


@app.route('/inbox')
@login_required
def inbox():
    partners = {}
    msgs = Message.query.filter(
        (Message.sender_id == current_user.id) | (Message.receiver_id == current_user.id)
    ).order_by(Message.created_at.desc()).all()

    for m in msgs:
        partner_id = m.receiver_id if m.sender_id == current_user.id else m.sender_id
        if partner_id not in partners:
            partners[partner_id] = {'last': m, 'count': 0}
        partners[partner_id]['count'] += 1

    partner_users = []
    for pid, info in partners.items():
        u = User.query.get(pid)
        if u:
            partner_users.append({'user': u, 'last': info['last'], 'count': info['count']})

    return render_template('inbox.html', partners=partner_users)


@app.route('/conversation/<int:partner_id>', methods=['GET','POST'])
@login_required
def conversation(partner_id):
    partner = User.query.get_or_404(partner_id)
    msgs = Message.query.filter(
        ((Message.sender_id==current_user.id) & (Message.receiver_id==partner_id)) |
        ((Message.sender_id==partner_id) & (Message.receiver_id==current_user.id))
    ).order_by(Message.created_at.asc()).all()

    if request.method == 'POST':
        text = request.form.get('text', '').strip()
        if text:
            m = Message(text=text, sender_id=current_user.id, receiver_id=partner_id)
            db.session.add(m)
            db.session.commit()
            return redirect(url_for('conversation', partner_id=partner_id))
    return render_template('conversation.html', partner=partner, messages=msgs)


# Serve uploads
@app.route('/uploads/<filename>')
def uploads(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


#if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
