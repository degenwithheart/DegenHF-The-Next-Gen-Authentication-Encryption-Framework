"""
Flask Integration Example for DegenHF ECC Authentication

This example shows how to integrate the ECC authentication package with Flask.
"""

FLASK_APP = """
# app.py

from flask import Flask, request, jsonify, g
from degenhf_flask import EccAuthHandler

app = Flask(__name__)

# Configure ECC authentication
app.config['ECC_HASH_ITERATIONS'] = 100000
app.config['ECC_TOKEN_EXPIRY'] = 3600  # 1 hour
app.config['ECC_CACHE_SIZE'] = 10000
app.config['ECC_CACHE_TTL'] = 300      # 5 minutes

# Initialize auth handler
auth_handler = EccAuthHandler()

@app.route('/api/auth/register', methods=['POST'])
def register():
    \"\"\"User registration endpoint\"\"\"
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        user_id = auth_handler.register(username, password)

        return jsonify({
            'status': 'success',
            'user_id': user_id,
            'message': 'User registered successfully'
        })

    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    \"\"\"User login endpoint\"\"\"
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

        token = auth_handler.authenticate(username, password)

        return jsonify({
            'status': 'success',
            'token': token,
            'message': 'Login successful'
        })

    except ValueError as e:
        return jsonify({'error': str(e)}), 401
    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/profile')
@auth_handler.token_required
def profile():
    \"\"\"Protected user profile endpoint\"\"\"
    try:
        user_data = auth_handler.get_current_user()

        return jsonify({
            'status': 'success',
            'user': {
                'id': user_data['id'],
                'username': user_data['username'],
                'created_at': user_data['created_at']
            }
        })

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/session', methods=['POST'])
@auth_handler.token_required
def create_session():
    \"\"\"Create user session endpoint\"\"\"
    try:
        user_data = auth_handler.get_current_user()
        session_data = auth_handler.create_session(user_data['id'])

        return jsonify({
            'status': 'success',
            'session': {
                'session_id': session_data['session_id'],
                'expires_at': session_data['expires_at']
            }
        })

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/auth/session/<session_id>')
def get_session(session_id):
    \"\"\"Get session information\"\"\"
    try:
        session_data = auth_handler.get_session(session_id)

        if not session_data:
            return jsonify({'error': 'Session not found or expired'}), 404

        return jsonify({
            'status': 'success',
            'session': {
                'session_id': session_data['session_id'],
                'user_id': session_data['user_id'],
                'created_at': session_data['created_at'],
                'expires_at': session_data['expires_at']
            }
        })

    except Exception as e:
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
"""

if __name__ == '__main__':
    print("Flask Integration Example")
    print("=" * 50)
    print()
    print("Create app.py with the following content:")
    print(FLASK_APP)
    print()
    print("Run the application:")
    print("   python app.py")
    print()
    print("Test the endpoints:")
    print("   POST /api/auth/register - Register a new user")
    print("   POST /api/auth/login - Login and get token")
    print("   GET /api/auth/profile - Get user profile (requires Bearer token)")
    print("   POST /api/auth/session - Create session (requires Bearer token)")
    print("   GET /api/auth/session/<session_id> - Get session info")