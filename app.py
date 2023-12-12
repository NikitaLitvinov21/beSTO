
from flask import Flask, redirect, render_template, url_for, request, abort, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, current_user
from werkzeug.security import check_password_hash

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
    status = db.Column(db.Enum('pending', 'in_progress', 'completed', name='order_status'))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    full_name = db.Column(db.String(255))

    def check_password(self, password):
        return check_password_hash(self.password, password)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    if current_user.is_authenticated:
        # Display all orders for authenticated users
        orders = Order.query.all()
        return render_template('index.html', orders=orders)

    # Display completed orders for non-authenticated users
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
            flash('Успішний вхід!', 'success')  # Flash success message
            return redirect(url_for('orders_index'))  # Redirect to orders page
        else:
            flash('Невірний логін або пароль', 'error')  # Flash error message
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

        user = User(email=email, password=password, full_name=full_name)
        db.session.add(user)
        db.session.commit()

        flash('Ви успішно зареєструвалися. Увійдіть зараз.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/orders')
def orders_index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    completed_orders = Order.query.filter_by(status='completed').all()
    return render_template('index.html', completed_orders=completed_orders)


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


@app.route('/orders/<int:order_id>')
def orders_detail(order_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    order = Order.query.get(order_id)
    if order is None:
        abort(404)
    return render_template('detail.html', order=order)


@app.route('/orders/<int:order_id>/edit', methods=['GET', 'POST'])
def orders_edit(order_id):
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
        order.car_number = car_number
        order.car_brand = car_brand
        order.car_year = car_year
        order.car_mileage = car_mileage
        order.repairs = repairs
        order.cost = cost
        order.mechanic = mechanic
        db.session.commit()
        return redirect(url_for('orders_index'))
    return render_template('edit.html', order=order)


@app.route('/orders/<int:order_id>/delete', methods=['POST'])
def orders_delete(order_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    order = Order.query.get(order_id)
    if order is None:
        abort(404)
    db.session.delete(order)
    db.session.commit()
    return redirect(url_for('orders_index'))


@app.route('/orders/<int:order_id>/start', methods=['POST'])
def orders_start(order_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    order = Order.query.get(order_id)
    if order is None:
        abort(404)
    order.status = 'in_progress'
    db.session.commit()
    return redirect(url_for('orders_index'))


@app.route('/orders/<int:order_id>/complete', methods=['POST'])
def orders_complete(order_id):
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    order = Order.query.get(order_id)
    if order is None:
        abort(404)
    order.status = 'completed'
    db.session.commit()
    return redirect(url_for('orders_index'))


def init_db():
    with app.app_context():
        db.create_all()
        existing_user = User.query.filter_by(email="admin@example.com").first()
        if existing_user is None:
            user = User(email="admin@example.com", password="password", full_name="Admin")
            db.session.add(user)
            db.session.commit()
        else:
            print("User with email 'admin@example.com' already exists.")

        order1 = Order(
            car_number="ABC123",
            car_brand="Toyota",
            car_year=2020,
            car_mileage=50000,
            repairs="Repairs for order 1",
            cost=1000.0,
            mechanic="John Doe",
            status='completed',
        )
        db.session.add(order1)

        order2 = Order(
            car_number="XYZ789",
            car_brand="Honda",
            car_year=2018,
            car_mileage=60000,
            repairs="Repairs for order 2",
            cost=1200.0,
            mechanic="Jane Smith",
            status='in_progress',
        )
        db.session.add(order2)

        order3 = Order(
            car_number="DEF456",
            car_brand="Ford",
            car_year=2019,
            car_mileage=55000,
            repairs="Repairs for order 3",
            cost=800.0,
            mechanic="Bob Johnson",
            status='pending',
        )
        db.session.add(order3)

        db.session.commit()


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()
        init_db()
    app.run(debug=True)
