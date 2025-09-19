# ACM BPDC Password Game

A horror-themed password game with progressive difficulty levels and real-time scoring.

## Features

🎯 **4-Difficulty Levels**: Easy, Medium, Hard, Impossible
🏆 **Real-time Scoring**: Progressive point system (5/10/15/25 points)
👻 **Horror Theme**: Scary fonts, ghostly animations, blood-red aesthetics
📊 **Admin Panel**: User management, live scoreboard, session monitoring
⚡ **Live Updates**: Real-time score tracking and admin monitoring
🎮 **ACM BPDC Integration**: Custom rules themed around ACM BPDC

## Installation

1. Install Python 3.8+
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Run the application:
   ```bash
   python app.py
   ```
4. Access the game at `http://localhost:5000`
5. Admin panel at `http://localhost:5000/admin` (login with default admin credentials)

## Admin Access

- **Username**: admin
- **Password**: admin123
- Change these in production!

## Deployment

### PythonAnywhere Deployment:
1. Upload all files to your PythonAnywhere account
2. Install requirements in a virtual environment
3. Set up the web app pointing to `app.py`
4. Configure static files if needed

### Local Development:
```bash
python app.py
```
Access at http://127.0.0.1:5000

## Game Rules

The game features progressive difficulty with ACM BPDC themed rules:
- **Easy Rules**: Basic character requirements (5 points each)
- **Medium Rules**: Pattern matching, specific characters (10 points each)  
- **Hard Rules**: Complex patterns, calculations (15 points each)
- **Impossible Rules**: Advanced logic, multiple constraints (25 points each)

## Features

- ✨ Smooth ghostly animations
- 📈 Real-time score updates
- 👥 Multi-user leaderboard
- 🔐 Admin authentication
- 📊 Comprehensive analytics
- 🎭 Horror-themed UI with scary fonts
- 📱 Responsive design

## Technical Stack

- **Backend**: Flask + SQLAlchemy
- **Database**: SQLite
- **Frontend**: HTML5 + CSS3 + Vanilla JavaScript
- **Fonts**: Google Fonts (Creepster, Metal Mania, Butcherman)
- **Authentication**: Flask-Bcrypt

## License

Created for ACM BPDC Events 2025
