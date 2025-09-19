from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
import time
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

app.config['SECRET_KEY'] = 'change-this-secret-key-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///password_game.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)  # can be email or display name
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(200), nullable=True)  # store Google name (if provided)
    password_hash = db.Column(db.String(128), nullable=True)  # allow null for OAuth users
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    score = db.Column(db.Integer, default=0)
    time_taken = db.Column(db.Integer)

    # UserMixin already provides is_active; keep compatibility
    def get_id(self):
        return str(self.id)

class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    check_function = db.Column(db.Text, nullable=False)
    difficulty = db.Column(db.String(20), nullable=False, default='easy')  # easy, medium, hard, impossible
    unlock_at = db.Column(db.Integer, nullable=False, default=0)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class GameSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(120), nullable=True)  # For guest or to store display name/email
    password_length = db.Column(db.Integer)
    time_taken = db.Column(db.Integer)  # in seconds
    rules_completed = db.Column(db.Integer)
    score = db.Column(db.Integer, default=0)  # Total score based on difficulty
    easy_completed = db.Column(db.Integer, default=0)
    medium_completed = db.Column(db.Integer, default=0)
    hard_completed = db.Column(db.Integer, default=0)
    impossible_completed = db.Column(db.Integer, default=0)
    completed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DifficultyConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    easy_count = db.Column(db.Integer, default=2)
    medium_count = db.Column(db.Integer, default=2)
    hard_count = db.Column(db.Integer, default=2)
    impossible_count = db.Column(db.Integer, default=2)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/index')
def index():
    return render_template('index.html')

google_bp = make_google_blueprint(
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    scope=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/userinfo.email"
    ],
    redirect_url="/google_post_auth"
)
app.register_blueprint(google_bp, url_prefix="/google_login")

@app.route("/google_post_auth")
def google_post_auth():
    if not google.authorized:
        flash("Google authorization failed. Please try again.", "error")
        return redirect(url_for("login"))

    try:
        resp = google.get("/oauth2/v2/userinfo")
    except Exception as e:
        flash(f"Error contacting Google: {e}", "error")
        return redirect(url_for("login"))

    if not resp.ok:
        flash(f"Google login failed: {resp.text}", "error")
        return redirect(url_for("login"))

    info = resp.json()
    print("DEBUG Google userinfo:", info)  # 👀 Check console for details

    email = info.get("email")
    name = info.get("name")
    fallback_username = (email.split("@")[0] if email else f"user_{int(time.time())}")

    if not email:
        flash("Google did not return an email. Please use a different account.", "error")
        return redirect(url_for("login"))

    # Check if user exists by email
    user = User.query.filter_by(email=email).first()
    if user:
        updated = False
        if name and user.full_name != name:
            user.full_name = name
            updated = True
        if user.username is None:
            user.username = name or fallback_username
            updated = True
        if updated:
            db.session.commit()
    else:
        username_to_use = name or fallback_username or email
        user = User(username=username_to_use, email=email, full_name=name, password_hash=None, is_admin=False)
        db.session.add(user)
        db.session.commit()

    # --- Handle session continuation or prevention ---
    thresholds = {
        "easy": 5,
        "medium": 15,  # Updated threshold for medium
        "hard": 120,
        "impossible": 160
    }

    # Check if the user has a completed session
    completed_session = GameSession.query.filter(
        GameSession.user_id == user.id,
        GameSession.completed == True,
        GameSession.score >= thresholds["impossible"]
    ).first()
    if completed_session:
        flash("You have already completed the game with this Google account. Only one full play allowed per account.", "error")
        return redirect(url_for("login"))

    # Check if the user has an existing session
    existing_session = GameSession.query.filter(
        GameSession.user_id == user.id
    ).order_by(GameSession.created_at.desc()).first()

    if existing_session:
        # Resume the session and always set next_level to "easy"
        flash("Welcome back! Resuming your progress.", "success")
        session["next_level"] = "easy"
    else:
        # Create a new session if none exists
        new_session = GameSession(
            user_id=user.id,
            username=user.username,
            password_length=0,
            time_taken=0,
            rules_completed=0,
            score=0,
            completed=False
        )
        db.session.add(new_session)
        db.session.commit()
        session["next_level"] = "easy"  # Start from the easy level
        flash("New session started. Good luck!", "success")
    # --- End session handling ---

    login_user(user)
    return redirect(url_for("index"))

@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('admin_login'))
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return redirect(url_for('admin_login'))
    
    # Get all rules
    rules = Rule.query.filter_by(is_active=True).order_by(Rule.unlock_at.desc()).all()
    
    # Get recent sessions
    recent_sessions = GameSession.query.order_by(GameSession.created_at.desc()).limit(10).all()
    
    # Calculate stats
    total_rules = Rule.query.filter_by(is_active=True).count()
    total_sessions = GameSession.query.count()
    completed_sessions = GameSession.query.filter_by(completed=True).count()
    
    # Calculate average time for completed sessions
    completed_times = [s.time_taken for s in GameSession.query.filter_by(completed=True).all() if s.time_taken]
    avg_time = sum(completed_times) / len(completed_times) if completed_times else 0
    
    stats = {
        'total_rules': total_rules,
        'total_sessions': total_sessions,
        'completed_sessions': completed_sessions,
        'avg_time': avg_time
    }
    
    return render_template('admin.html', user=user, rules=rules, recent_sessions=recent_sessions, stats=stats)

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password_hash and bcrypt.check_password_hash(user.password_hash, password) and user.is_admin:
            session['user_id'] = user.id
            return redirect(url_for('admin'))
        else:
            return render_template('admin_login.html', error='Invalid credentials or not an admin')
    
    return render_template('admin_login.html')

@app.route('/logout')
def logout():
    # log out Flask-Login user if present
    try:
        logout_user()
    except Exception:
        pass
    # keep existing session clearing logic for admin sessions
    session.pop('user_id', None)
    return redirect(url_for('index'))

# API Routes
@app.route('/api/rules')
def get_rules():
    # Get difficulty configuration
    config = DifficultyConfig.query.first()
    if not config:
        config = DifficultyConfig()
        db.session.add(config)
        db.session.commit()
    
    # Get rules by difficulty level based on configuration
    difficulties = ['easy', 'medium', 'hard', 'impossible']
    counts = [config.easy_count, config.medium_count, config.hard_count, config.impossible_count]
    selected_rules = []
    
    import random
    for i, (difficulty, count) in enumerate(zip(difficulties, counts)):
        # Get all rules for this difficulty
        difficulty_rules = Rule.query.filter_by(is_active=True, difficulty=difficulty).all()
        
        if difficulty_rules and count > 0:
            # Randomly select rules from this difficulty
            selected_count = min(count, len(difficulty_rules))
            for j in range(selected_count):
                if difficulty_rules:
                    selected_rule = random.choice(difficulty_rules)
                    difficulty_rules.remove(selected_rule)  # Avoid duplicates
                    # Set unlock_at based on current position
                    selected_rule.unlock_at = len(selected_rules)
                    selected_rules.append(selected_rule)
    
    return jsonify({
        'rules': [{
            'id': rule.id,
            'text': rule.text,
            'check_function': rule.check_function,
            'unlock_at': rule.unlock_at,
            'difficulty': rule.difficulty
        } for rule in selected_rules]
    })

@app.route('/api/difficulty-config')
def get_difficulty_config():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    config = DifficultyConfig.query.first()
    if not config:
        config = DifficultyConfig()
        db.session.add(config)
        db.session.commit()
    
    return jsonify({
        'easy_count': config.easy_count,
        'medium_count': config.medium_count,
        'hard_count': config.hard_count,
        'impossible_count': config.impossible_count
    })

@app.route('/api/difficulty-config', methods=['POST'])
def update_difficulty_config():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json() or {}
    config = DifficultyConfig.query.first()
    if not config:
        config = DifficultyConfig()
        db.session.add(config)
    
    config.easy_count = data.get('easy_count', 2)
    config.medium_count = data.get('medium_count', 2)
    config.hard_count = data.get('hard_count', 2)
    config.impossible_count = data.get('impossible_count', 2)
    config.updated_at = datetime.utcnow()
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Configuration updated successfully'})

@app.route('/api/admin/users')
def get_all_users():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    # Get all users with their best scores and total times
    users_data = []
    all_users = User.query.all()
    
    for user_record in all_users:
        # Get best session for this user
        best_session = GameSession.query.filter_by(user_id=user_record.id, completed=True).order_by(GameSession.score.desc(), GameSession.time_taken.asc()).first()
        
        # Get total time and sessions count
        user_sessions = GameSession.query.filter_by(user_id=user_record.id).all()
        total_time = sum(s.time_taken for s in user_sessions if s.time_taken)
        sessions_count = len(user_sessions)
        
        users_data.append({
            'id': user_record.id,
            'username': user_record.username,
            'email': user_record.email,
            'full_name': user_record.full_name or '',
            'best_score': best_session.score if best_session else 0,
            'best_time': best_session.time_taken if best_session else 0,
            'total_time': total_time,
            'sessions_count': sessions_count,
            'created_at': user_record.created_at.strftime('%Y-%m-%d'),
            'is_admin': user_record.is_admin
        })
    
    # Also get guest sessions
    guest_sessions = GameSession.query.filter(GameSession.user_id.is_(None)).all()
    guest_users = {}
    
    for gs in guest_sessions:
        username_display = gs.username or 'Guest'
        if username_display not in guest_users:
            guest_users[username_display] = {
                'username': username_display,
                'email': 'N/A',
                'best_score': 0,
                'best_time': 0,
                'total_time': 0,
                'sessions_count': 0,
                'created_at': 'N/A',
                'is_admin': False
            }
        
        guest_users[username_display]['sessions_count'] += 1
        if gs.time_taken:
            guest_users[username_display]['total_time'] += gs.time_taken
        
        if gs.completed and gs.score > guest_users[username_display]['best_score']:
            guest_users[username_display]['best_score'] = gs.score
            guest_users[username_display]['best_time'] = gs.time_taken or 0
    
    users_data.extend(list(guest_users.values()))
    
    return jsonify({'users': users_data})

@app.route('/api/admin/rules')
def get_all_rules():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    rules = Rule.query.order_by(Rule.unlock_at).all()
    return jsonify({
        'rules': [{
            'id': rule.id,
            'text': rule.text,
            'check_function': rule.check_function,
            'unlock_at': rule.unlock_at,
            'is_active': rule.is_active,
            'created_at': rule.created_at.strftime('%Y-%m-%d'),
            'created_by': (User.query.get(rule.created_by).username if User.query.get(rule.created_by) else 'Unknown')
        } for rule in rules]
    })

@app.route('/api/admin/rules', methods=['POST'])
def create_rule():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json() or {}
    
    # Get the highest unlock_at value for this difficulty
    difficulty = data.get('difficulty', 'easy')
    max_unlock_at = db.session.query(db.func.max(Rule.unlock_at)).filter_by(difficulty=difficulty).scalar() or -1
    
    rule = Rule(
        text=data['text'],
        check_function=data['check_function'],
        difficulty=difficulty,
        unlock_at=max_unlock_at + 1,
        created_by=user.id
    )
    
    db.session.add(rule)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Rule created successfully'})

@app.route('/api/admin/rules/<int:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    rule = Rule.query.get_or_404(rule_id)
    data = request.get_json() or {}
    
    if 'text' in data:
        rule.text = data['text']
    if 'check_function' in data:
        rule.check_function = data['check_function']
    if 'unlock_at' in data:
        rule.unlock_at = data['unlock_at']
    if 'is_active' in data:
        rule.is_active = data['is_active']
    
    db.session.commit()
    return jsonify({'message': 'Rule updated successfully'})

@app.route('/api/admin/rules/<int:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    rule = Rule.query.get_or_404(rule_id)
    db.session.delete(rule)  # Actually delete instead of just deactivating
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Rule deleted successfully'})

@app.route('/api/admin/stats')
def get_admin_stats():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    total_rules = Rule.query.filter_by(is_active=True).count()
    total_sessions = GameSession.query.count()
    completed_sessions = GameSession.query.filter_by(completed=True).count()
    
    # Calculate average time for completed sessions
    completed_times = [s.time_taken for s in GameSession.query.filter_by(completed=True).all() if s.time_taken]
    avg_time = sum(completed_times) / len(completed_times) if completed_times else 0
    
    return jsonify({
        'total_rules': total_rules,
        'total_sessions': total_sessions,
        'completed_sessions': completed_sessions,
        'avg_time': avg_time
    })

@app.route('/api/admin/scoreboard')
def admin_scoreboard():
    if 'user_id' not in session:
        return jsonify({'error': 'Admin access required'}), 401
    
    # This endpoint returns a scoreboard grouped by username (including logged in users)
    try:
        # We'll compute aggregated stats grouped by either user_id (if present) or username string for guests
        # Simpler approach: get top sessions ordered by score and collect per unique actor
        sessions = GameSession.query.filter_by(completed=True).order_by(GameSession.score.desc(), GameSession.time_taken.asc()).all()
        seen = set()
        scoreboard = []
        for s in sessions:
            key = s.user_id if s.user_id is not None else (s.username or f"guest_{s.id}")
            if key in seen:
                continue
            seen.add(key)
            display_name = s.username or 'Guest'
            if s.user_id:
                u = User.query.get(s.user_id)
                if u:
                    display_name = u.full_name or u.username or u.email
            scoreboard.append({
                'username': display_name,
                'score': s.score or 0,
                'time_taken': s.time_taken or 0,
                'password_length': s.password_length,
                'rules_completed': s.rules_completed,
                'last_played': s.created_at.strftime('%Y-%m-%d %H:%M')
            })
            if len(scoreboard) >= 50:  # safety cap
                break

        return jsonify({'scoreboard': scoreboard})
    except Exception as e:
        print(f"Scoreboard error: {e}")
        return jsonify({'error': 'Failed to load scoreboard'}), 500

@app.route('/api/admin/recent-sessions')
def get_recent_sessions():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user = User.query.get(session['user_id'])
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403
    
    sessions = GameSession.query.order_by(GameSession.created_at.desc()).limit(10).all()
    
    return jsonify({
        'sessions': [{
            'username': (User.query.get(s.user_id).full_name if s.user_id and User.query.get(s.user_id) else s.username or 'Guest'),
            'time_taken': s.time_taken or 0,
            'rules_completed': s.rules_completed or 0,
            'completed': s.completed
        } for s in sessions]
    })

@app.route('/update_score', methods=['POST'])
def update_score():
    try:
        data = request.get_json() or {}
        current_score = data.get('current_score', 0)
        password = data.get('password', '')

        if current_user.is_authenticated:
            username = current_user.full_name or current_user.username or current_user.email
            user_id = current_user.id
        else:
            username = f"Player_{request.remote_addr.replace('.', '_')}_{int(time.time() // 3600)}"
            user_id = None

        active_session = GameSession.query.filter_by(
            username=username,
            completed=False
        ).order_by(GameSession.created_at.desc()).first()

        current_time = datetime.utcnow()
        level_cleared = False
        cleared_level_message = None

        # Get difficulty configuration for correct easy threshold
        config = DifficultyConfig.query.first()
        easy_threshold = 5  # Only 1 easy rule

        thresholds = {
            "easy": easy_threshold,
            "medium": 15,  # Updated threshold for medium
            "hard": 120,
            "impossible": 160
        }

        # Always set previous_score, even for new session
        previous_score = 0
        if not active_session:
            active_session = GameSession(
                user_id=user_id,
                username=username,
                password_length=len(password),
                time_taken=0,
                rules_completed=0,
                score=current_score,
                completed=False
            )
            db.session.add(active_session)

        else:
            previous_score = active_session.score or 0  # Get previous score before updating
            active_session.user_id = user_id or active_session.user_id
            active_session.username = username or active_session.username
            active_session.password_length = len(password)
            # Always update score to current_score
            active_session.score = current_score
            active_session.time_taken = int((current_time - active_session.created_at).total_seconds())

        # Update User table for logged-in users if this is a new best score
        if current_user.is_authenticated:
            user_record = User.query.get(current_user.id)
            if user_record:
                # Update if this is a new best score or first score
                if not user_record.score or current_score > user_record.score:
                    user_record.score = current_score
                    user_record.time_taken = active_session.time_taken

        # Detect level completion (show message only when crossing threshold)
        for level, points in thresholds.items():
            print(f"DEBUG: Level={level}, Threshold={points}, Previous={previous_score}, Current={current_score}")
            if points <= current_score:
                level_cleared = True
                if level == "easy":
                    cleared_level_message = "🎉 Easy level completed! Moving to Medium!"
                elif level == "medium":
                    cleared_level_message = "🔥 Medium level completed! Now Hard!"
                elif level == "hard":
                    cleared_level_message = "💀 Hard level completed! Impossible awaits!"
                elif level == "impossible":
                    cleared_level_message = "🏆 Impossible completed! You beat the game!"

        db.session.commit()

        return jsonify({
            'success': True,
            'score': current_score,
            'session_id': active_session.id,
            'level_cleared': level_cleared,
            'cleared_level_message': cleared_level_message
        })

    except Exception as e:
        print(f"Score update error: {e}")
        return jsonify({'error': 'Update failed'}), 500

@app.route('/api/save-session', methods=['POST'])
def save_session():
    data = request.get_json() or {}
    
    # Calculate score based on difficulty completion
    # Easy: 5 points, Medium: 10 points, Hard: 15 points, Impossible: 25 points
    easy_completed = int(data.get('easy_completed', 0))
    medium_completed = int(data.get('medium_completed', 0))
    hard_completed = int(data.get('hard_completed', 0))
    impossible_completed = int(data.get('impossible_completed', 0))
    
    score = (easy_completed * 5) + (medium_completed * 10) + (hard_completed * 15) + (impossible_completed * 25)
    time_taken = data.get('time_taken', 0)
    
    # If a logged-in user is saving, associate the session with them
    user_id = None
    username_for_record = data.get('username', None)
    if current_user.is_authenticated:
        user_id = current_user.id
        username_for_record = current_user.full_name or current_user.username or current_user.email

    session_record = GameSession(
        user_id=user_id,
        username=username_for_record or 'Guest',
        password_length=data.get('password_length'),
        time_taken=time_taken,
        rules_completed=data.get('rules_completed'),
        score=score,
        easy_completed=easy_completed,
        medium_completed=medium_completed,
        hard_completed=hard_completed,
        impossible_completed=impossible_completed,
        completed=bool(data.get('completed', False))
    )
    
    db.session.add(session_record)
    
    # Update User table for logged-in users
    if current_user.is_authenticated:
        user_record = User.query.get(current_user.id)
        if user_record:
            # Update if this is a new best score or first score, or if completed
            if (not user_record.score or score > user_record.score) or session_record.completed:
                user_record.score = score
                user_record.time_taken = time_taken
    
    db.session.commit()
    
    return jsonify({
        'message': 'Session saved successfully',
        'score': score,
        'breakdown': {
            'easy': easy_completed * 5,
            'medium': medium_completed * 10,
            'hard': hard_completed * 15,
            'impossible': impossible_completed * 25
        }
    })

@app.route('/api/leaderboard')
def get_leaderboard():
    # Top completed sessions
    sessions = GameSession.query.filter_by(completed=True).order_by(GameSession.score.desc(), GameSession.time_taken.asc()).all()
    
    leaderboard = []
    seen_users = set()  # Track users to avoid duplicates
    for s in sessions:
        user_key = s.user_id if s.user_id else s.username  # Use user_id if available, else username for guests
        if user_key in seen_users:
            continue  # Skip duplicate entries
        seen_users.add(user_key)

        display_username = s.username or 'Guest'
        display_email = None
        # If session is tied to user_id, prefer that user's info
        if s.user_id:
            u = User.query.get(s.user_id)
            if u:
                display_username = u.full_name or u.username or u.email
                display_email = u.email
        leaderboard.append({
            'username': display_username,
            'email': display_email or 'N/A',
            'score': s.score or 0,
            'time_taken': s.time_taken,
            'password_length': s.password_length,
            'rules_completed': s.rules_completed,
            'completed_at': s.created_at.strftime('%Y-%m-%d %H:%M')
        })
        if len(leaderboard) >= 10:  # Limit to top 10 entries
            break

    return jsonify({'leaderboard': leaderboard})

@app.route('/api/next_level')
def get_next_level():
    next_level = session.get("next_level", "easy")  # Default to "easy" if not set
    return jsonify({"next_level": next_level})

def init_database():
    """Initialize database with default data"""
    with app.app_context():
        db.create_all()
        
        # Create admin user if doesn't exist
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
            admin_user = User(
                username='admin',
                email='admin@passwordgame.com',
                full_name='Admin',
                password_hash=admin_password,
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()
            
            # Add default rules for each difficulty level with ACM BPDC themes
            default_rules = {
                'easy': [
                    {'text': 'Your password must be at least 5 characters.', 'check_function': 'password.length >= 5'},
                    {'text': 'Your password must include a number.', 'check_function': '/\\d/.test(password)'},
                    {'text': 'Your password must include an uppercase letter.', 'check_function': '/[A-Z]/.test(password)'},
                    {'text': 'Your password must include a lowercase letter.', 'check_function': '/[a-z]/.test(password)'},
                    {'text': 'Your password must be at least 8 characters.', 'check_function': 'password.length >= 8'},
                    {'text': 'Your password must include a special character.', 'check_function': '/[!@#$%^&*]/.test(password)'},
                    {'text': 'Your password must include "ACM".', 'check_function': 'password.toUpperCase().includes("ACM")'},
                    {'text': 'Your password must include at least 2 numbers.', 'check_function': '(password.match(/\\d/g) || []).length >= 2'},
                    {'text': 'Your password must include "BITS".', 'check_function': 'password.toUpperCase().includes("BITS")'},
                    {'text': 'Your password must include "BPDC".', 'check_function': 'password.toUpperCase().includes("BPDC")'}
                ],
                'medium': [
                    {'text': 'Your password must include "Programming".', 'check_function': 'password.toLowerCase().includes("programming")'},
                    {'text': 'Your password must include the current year (2025).', 'check_function': 'password.includes("2025")'},
                    {'text': 'Your password must have digits that add up to 25.', 'check_function': '(password.match(/\\d/g) || []).reduce((sum, digit) => sum + parseInt(digit), 0) === 25'},
                    {'text': 'Your password must include "Dubai".', 'check_function': 'password.toLowerCase().includes("dubai")'},
                    {'text': 'Your password must include a color.', 'check_function': '/red|blue|green|yellow|purple|orange|pink|black|white|brown/i.test(password)'},
                    {'text': 'Your password must include "250" (our member count).', 'check_function': 'password.includes("250")'},
                    {'text': 'Your password must be at least 15 characters.', 'check_function': 'password.length >= 15'},
                    {'text': 'Your password must include "Computing".', 'check_function': 'password.toLowerCase().includes("computing")'},
                    {'text': 'Your password must include at least 3 vowels.', 'check_function': '(password.match(/[aeiouAEIOU]/g) || []).length >= 3'},
                    {'text': 'Your password must include "Chapter".', 'check_function': 'password.toLowerCase().includes("chapter")'}
                ],
                'hard': [
                    {'text': 'Your password must include "CyberSecurity" (one of our SIGs).', 'check_function': 'password.toLowerCase().includes("cybersecurity")'},
                    {'text': 'Your password must include "AI" (Artificial Intelligence SIG).', 'check_function': 'password.toUpperCase().includes("AI")'},
                    {'text': 'Your password must include "CP" (Competitive Programming SIG).', 'check_function': 'password.toUpperCase().includes("CP")'},
                    {'text': 'Your password must include π (3.14).', 'check_function': 'password.includes("3.14")'},
                    {'text': 'Your password must include "Dev" (Development SIG).', 'check_function': 'password.toLowerCase().includes("dev")'},
                    {'text': 'Your password must include "ML" (Machine Learning).', 'check_function': 'password.toUpperCase().includes("ML")'},
                    {'text': 'Your password must be at least 20 characters.', 'check_function': 'password.length >= 20'},
                    {'text': 'Your password must include a programming language.', 'check_function': '/python|javascript|java|cpp|ruby|go|rust|swift/i.test(password)'},
                    {'text': 'Your password must include "45000" (our social media impressions).', 'check_function': 'password.includes("45000")'},
                    {'text': 'Your password must include "Excellence" (our award).', 'check_function': 'password.toLowerCase().includes("excellence")'}
                ],
                'impossible': [
                    {'text': 'Your password must include "Outstanding School Service 2024" (our recent award).', 'check_function': 'password.toLowerCase().includes("outstanding")'},
                    {'text': 'Your password must include "Mouseless X Keyboardless" (our recent event).', 'check_function': 'password.toLowerCase().includes("mouseless")'},
                    {'text': 'Your password must be exactly 35 characters.', 'check_function': 'password.length === 35'},
                    {'text': 'Your password must include "-1/12" (days since spacetime mess).', 'check_function': 'password.includes("-1/12")'},
                    {'text': 'Your password must include "acmbpdc.org".', 'check_function': 'password.toLowerCase().includes("acmbpdc.org")'},
                    {'text': 'Your password must end with the first letter.', 'check_function': 'password.length > 0 && password[0] === password[password.length - 1]'},
                    {'text': 'Your password must include "200+" (our cumulative events).', 'check_function': 'password.includes("200+")'},
                    {'text': 'Your password must include "Pilani".', 'check_function': 'password.toLowerCase().includes("pilani")'},
                    {'text': 'Your password must have more vowels than consonants.', 'check_function': '(password.match(/[aeiouAEIOU]/g) || []).length > (password.match(/[bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ]/g) || []).length'},
                    {'text': 'Your password must include "PROGRESSING TOGETHER".', 'check_function': 'password.toUpperCase().includes("PROGRESSING TOGETHER")'}
                ]
            }
            
            for difficulty, rules_list in default_rules.items():
                for i, rule_data in enumerate(rules_list):
                    rule = Rule(
                        text=rule_data['text'],
                        check_function=rule_data['check_function'],
                        difficulty=difficulty,
                        unlock_at=i,
                        created_by=admin_user.id
                    )
                    db.session.add(rule)
            
            db.session.commit()
            print("Database initialized with admin user and difficulty-based rules!")


if __name__ == '__main__':
    init_database()
    app.run(debug=True, host='0.0.0.0', port=5000)