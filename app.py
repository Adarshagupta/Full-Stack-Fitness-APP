from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import bcrypt
import jwt
import os
import secrets
from functools import wraps
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configure the PostgreSQL database
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://nam_d2fh_user:MYFMw6Or9EGQy2aCwJOY4nLoGoBQfl46@dpg-critqglumphs73cqosk0-a.oregon-postgres.render.com/nam_d2fh'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Add a secret key for JWT
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'your-secret-key')
jwt = JWTManager(app)

# Define models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    height = db.Column(db.Float)
    weight = db.Column(db.Float)
    age = db.Column(db.Integer)
    gender = db.Column(db.String(10))

class Food(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    calories = db.Column(db.Float, nullable=False)
    protein = db.Column(db.Float)
    carbs = db.Column(db.Float)
    fat = db.Column(db.Float)
    barcode = db.Column(db.String(50), unique=True)

class FoodEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    food_id = db.Column(db.Integer, db.ForeignKey('food.id'), nullable=False)
    quantity = db.Column(db.Float, nullable=False)
    meal_type = db.Column(db.String(20))  # e.g., breakfast, lunch, dinner, snack
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Exercise(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    calories_burned = db.Column(db.Float)
    duration = db.Column(db.Integer)  # in minutes

class ExerciseEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    exercise_id = db.Column(db.Integer, db.ForeignKey('exercise.id'), nullable=False)
    duration = db.Column(db.Integer)  # in minutes
    date = db.Column(db.DateTime, default=datetime.utcnow)

class WaterIntake(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)  # in ml
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Sleep(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    quality = db.Column(db.Integer)  # 1-10 scale

class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    goal_type = db.Column(db.String(50), nullable=False)  # e.g., weight_loss, muscle_gain, etc.
    target_value = db.Column(db.Float, nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.utcnow)
    end_date = db.Column(db.DateTime)

# Create the database tables
with app.app_context():
    db.create_all()

# Add this function to reset all passwords
def reset_all_passwords():
    users = User.query.all()
    for user in users:
        # Generate a secure random password
        temp_password = secrets.token_urlsafe(12)
        hashed_password = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt())
        user.password = hashed_password.decode('utf-8')
        print(f"Reset password for user {user.username} to: {temp_password}")
    db.session.commit()
    print("All passwords have been reset.")

# Add this route to trigger the password reset (remove or secure this route after use)
@app.route('/api/reset_all_passwords', methods=['POST'])
def trigger_reset_all_passwords():
    reset_all_passwords()
    return jsonify({"message": "All passwords have been reset"}), 200

# API routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password.decode('utf-8'),  # Store as string
        height=data.get('height'),
        weight=data.get('weight'),
        age=data.get('age'),
        gender=data.get('gender')
    )
    db.session.add(new_user)
    try:
        db.session.commit()
        return jsonify({"message": "User registered successfully"}), 201
    except:
        db.session.rollback()
        return jsonify({"message": "Username or email already exists"}), 400

@app.route('/api/login', methods=['POST'])
def login():
    print("Received login request")
    print("Request data:", request.json)
    try:
        data = request.json
        user = User.query.filter_by(username=data['username']).first()
        if user and bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
            access_token = create_access_token(identity=user.id)
            response_data = {"access_token": access_token, "user_id": user.id, "username": user.username}
            print("Login response:", response_data)
            return jsonify(response_data), 200
        else:
            print("Login failed: Invalid username or password")
            return jsonify({"message": "Invalid username or password"}), 401
    except Exception as e:
        print("Login error:", str(e))
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"message": "An error occurred during login"}), 500

@app.route('/api/food_entry', methods=['POST'])
@jwt_required()
def add_food_entry():
    current_user = get_jwt_identity()
    data = request.json
    new_entry = FoodEntry(
        user_id=current_user,
        food_id=data['food_id'],
        quantity=data['quantity'],
        meal_type=data['meal_type']
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"message": "Food entry added successfully"}), 201

@app.route('/api/exercise_entry', methods=['POST'])
@jwt_required()
def add_exercise_entry():
    current_user = get_jwt_identity()
    data = request.json
    new_entry = ExerciseEntry(
        user_id=current_user,
        exercise_id=data['exercise_id'],
        duration=data['duration']
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"message": "Exercise entry added successfully"}), 201

@app.route('/api/water_intake', methods=['POST'])
@jwt_required()
def add_water_intake():
    current_user = get_jwt_identity()
    data = request.json
    new_entry = WaterIntake(
        user_id=current_user,
        amount=data['amount']
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"message": "Water intake added successfully"}), 201

@app.route('/api/sleep', methods=['POST'])
@jwt_required()
def add_sleep_entry():
    current_user = get_jwt_identity()
    data = request.json
    new_entry = Sleep(
        user_id=current_user,
        start_time=datetime.fromisoformat(data['start_time']),
        end_time=datetime.fromisoformat(data['end_time']),
        quality=data.get('quality')
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({"message": "Sleep entry added successfully"}), 201

@app.route('/api/goal', methods=['POST'])
@jwt_required()
def set_goal():
    current_user = get_jwt_identity()
    data = request.json
    new_goal = Goal(
        user_id=current_user,
        goal_type=data['goal_type'],
        target_value=data['target_value'],
        end_date=datetime.fromisoformat(data['end_date'])
    )
    db.session.add(new_goal)
    db.session.commit()
    return jsonify({"message": "Goal set successfully"}), 201

@app.route('/api/food_search', methods=['GET'])
def search_food():
    query = request.args.get('q')
    foods = Food.query.filter(Food.name.ilike(f'%{query}%')).all()
    return jsonify([{
        'id': food.id,
        'name': food.name,
        'calories': food.calories,
        'protein': food.protein,
        'carbs': food.carbs,
        'fat': food.fat
    } for food in foods])

@app.route('/api/barcode_scan', methods=['POST'])
def scan_barcode():
    barcode_data = request.json['barcode']
    food = Food.query.filter_by(barcode=barcode_data).first()
    if food:
        return jsonify({
            'id': food.id,
            'name': food.name,
            'calories': food.calories,
            'protein': food.protein,
            'carbs': food.carbs,
            'fat': food.fat
        })
    else:
        return jsonify({"message": "Food not found"}), 404

@app.route('/api/daily_summary/<int:user_id>')
@jwt_required()
def get_daily_summary(user_id):
    today = datetime.utcnow().date()
    food_entries = FoodEntry.query.filter(
        FoodEntry.user_id == user_id,
        FoodEntry.date >= today
    ).all()
    exercise_entries = ExerciseEntry.query.filter(
        ExerciseEntry.user_id == user_id,
        ExerciseEntry.date >= today
    ).all()
    water_intake = WaterIntake.query.filter(
        WaterIntake.user_id == user_id,
        WaterIntake.date >= today
    ).all()

    total_calories = sum(entry.food.calories * entry.quantity for entry in food_entries)
    total_protein = sum(entry.food.protein * entry.quantity for entry in food_entries if entry.food.protein)
    total_carbs = sum(entry.food.carbs * entry.quantity for entry in food_entries if entry.food.carbs)
    total_fat = sum(entry.food.fat * entry.quantity for entry in food_entries if entry.food.fat)
    total_water = sum(entry.amount for entry in water_intake)
    total_exercise_duration = sum(entry.duration for entry in exercise_entries)
    total_calories_burned = sum(entry.exercise.calories_burned * (entry.duration / 60) for entry in exercise_entries if entry.exercise.calories_burned)

    # Calculate calories goal (example: 2000 calories per day)
    calories_goal = 2000

    return jsonify({
        "calories_consumed": total_calories,
        "calories_goal": calories_goal,
        "protein": total_protein,
        "carbs": total_carbs,
        "fat": total_fat,
        "water_intake": total_water,
        "exercise_duration": total_exercise_duration,
        "calories_burned": total_calories_burned
    })

@app.route('/api/add_food', methods=['POST'])
@jwt_required()
def add_food():
    current_user = get_jwt_identity()
    data = request.json
    new_food = Food(
        name=data['name'],
        calories=data['calories'],
        protein=data.get('protein'),
        carbs=data.get('carbs'),
        fat=data.get('fat')
    )
    db.session.add(new_food)
    db.session.commit()

    new_entry = FoodEntry(
        user_id=current_user,
        food_id=new_food.id,
        quantity=data['quantity'],
        meal_type=data['meal_type']
    )
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"message": "Food added and logged successfully"}), 201

@app.route('/api/log_exercise', methods=['POST'])
@jwt_required()
def log_exercise():
    current_user = get_jwt_identity()
    data = request.json
    new_exercise = Exercise(
        name=data['name'],
        calories_burned=data['calories_burned'],
        duration=data['duration']
    )
    db.session.add(new_exercise)
    db.session.commit()

    new_entry = ExerciseEntry(
        user_id=current_user,
        exercise_id=new_exercise.id,
        duration=data['duration']
    )
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"message": "Exercise logged successfully"}), 201

@app.route('/api/log_water', methods=['POST'])
@jwt_required()
def log_water():
    current_user = get_jwt_identity()
    data = request.json
    new_entry = WaterIntake(
        user_id=current_user,
        amount=data['amount']
    )
    db.session.add(new_entry)
    db.session.commit()

    return jsonify({"message": "Water intake logged successfully"}), 201

@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected_route():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Hello, user {current_user}! This is a protected route."})

@app.route('/api/user/<int:user_id>', methods=['GET'])
@jwt_required()
def get_user_data(user_id):
    try:
        current_user = get_jwt_identity()
        if current_user != user_id:
            return jsonify({"message": "Unauthorized access"}), 403
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        return jsonify({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "height": user.height,
            "weight": user.weight,
            "age": user.age,
            "gender": user.gender
        }), 200
    except Exception as e:
        app.logger.error(f"Error fetching user data: {str(e)}")
        return jsonify({"message": "An error occurred while fetching user data"}), 500

@app.route('/api/change_password', methods=['POST'])
@jwt_required()
def change_password():
    current_user = get_jwt_identity()
    user = User.query.get(current_user)
    data = request.json
    if bcrypt.checkpw(data['old_password'].encode('utf-8'), user.password.encode('utf-8')):
        new_hashed_password = bcrypt.hashpw(data['new_password'].encode('utf-8'), bcrypt.gensalt())
        user.password = new_hashed_password.decode('utf-8')
        db.session.commit()
        return jsonify({"message": "Password changed successfully"}), 200
    else:
        return jsonify({"message": "Invalid old password"}), 400

@app.errorhandler(Exception)
def handle_exception(e):
    # Log the error
    app.logger.error(f"Unhandled exception: {str(e)}", exc_info=True)
    # Return JSON instead of HTML for HTTP errors
    return jsonify(error=str(e)), 500

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)