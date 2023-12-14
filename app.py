from flask import Flask, redirect, render_template, url_for, request, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user, UserMixin
from werkzeug.security import check_password_hash
from werkzeug.security import generate_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1223@localhost/postgres'
app.config['SECRET_KEY'] = '1223'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    car_number = db.Column(db.String(10))
    car_brand = db.Column(db.String(20))
    car_year = db.Column(db.Integer)
    car_mileage = db.Column(db.Integer)
    repairs = db.Column(db.String(255))
    cost = db.Column(db.Float)
    mechanic = db.Column(db.String(20))
    status = db.Column(db.Enum('pending', 'in_progress', 'completed', name='status'))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    full_name = db.Column(db.String(255))

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return str(self.id)

    def check_password(self, password):
        return check_password_hash(self.password, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    if current_user.is_authenticated:
        orders = Order.query.all()
        return render_template('index.html', orders=orders)

    completed_orders = Order.query.filter_by(status='completed').all()
    return render_template('index.html', completed_orders=completed_orders)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Успішний вхід!', 'success')
            return redirect(url_for('orders_index'))
        else:
            flash('Невірний логін або пароль', 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        full_name = request.form['full_name']

        if User.query.filter_by(email=email).first():
            flash('Ця адреса електронної пошти вже зареєстрована')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        user = User(email=email, password=hashed_password, full_name=full_name)
        db.session.add(user)
        db.session.commit()

        flash('Ви успішно зареєструвалися. Увійдіть зараз.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/orders', methods=['GET', 'POST'])
def orders_index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    orders = Order.query.all()

    if request.method == 'POST':
        if 'edit' in request.form:
            order_id = int(request.form['edit'])
            return redirect(url_for('edit_order', order_id=order_id))
        elif 'delete' in request.form:
            order_id = int(request.form['delete'])
            order = Order.query.get(order_id)
            if order:
                db.session.delete(order)
                db.session.commit()
                return redirect(url_for('orders_index'))

    return render_template('orders_index.html', orders=orders)


@app.route('/create', methods=['GET', 'POST'])
def orders_create():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    if request.method == 'POST':
        car_number = request.form['car_number']
        car_brand = request.form['car_brand']
        car_year = request.form['car_year']
        car_mileage = request.form['car_mileage']
        repairs = request.form['repairs']
        cost = request.form['cost']
        mechanic = request.form['mechanic']
        order = Order(
            car_number=car_number,
            car_brand=car_brand,
            car_year=car_year,
            car_mileage=car_mileage,
            repairs=repairs,
            cost=cost,
            mechanic=mechanic,
            status='pending',
        )
        db.session.add(order)
        db.session.commit()
        return redirect(url_for('orders_index'))
    return render_template('create.html')


@app.route('/edit/<int:order_id>', methods=['GET', 'POST'])
def edit_order(order_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))

    order = Order.query.get(order_id)

    if order is None:
        abort(404)

    if request.method == 'POST':
        car_number = request.form['car_number']
        car_brand = request.form['car_brand']
        car_year = request.form['car_year']
        car_mileage = request.form['car_mileage']
        repairs = request.form['repairs']
        cost = request.form['cost']
        mechanic = request.form['mechanic']
        status = request.form['status']

        order.car_number = car_number
        order.car_brand = car_brand
        order.car_year = car_year
        order.car_mileage = car_mileage
        order.repairs = repairs
        order.cost = cost
        order.mechanic = mechanic
        order.status = status
        db.session.commit()

        return redirect(url_for('orders_index'))

    return render_template('edit.html', order=order, order_id=order_id)


def init_db():
    with app.app_context():
        db.create_all()
        db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
