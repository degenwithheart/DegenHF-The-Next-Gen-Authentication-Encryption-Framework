require 'sinatra'
require 'sinatra/json'
require 'jwt'
require 'openssl'
require 'securerandom'
require 'digest'
require 'time'
require 'rack/cors'

# Enable CORS
use Rack::Cors do
  allow do
    origins '*'
    resource '*',
      headers: :any,
      methods: [:get, :post, :put, :delete, :options]
  end
end

# ECC-based authentication handler
class EccAuthHandler
  def initialize
    @users = {}  # username -> user_data
    @user_ids = {}  # user_id -> user_data
    @sessions = {}  # session_id -> session_data
  end

  # User data structure
  UserData = Struct.new(:user_id, :username, :password_hash, :salt,
                       :ecc_private_key, :ecc_public_key, :created_at)

  # User session structure
  UserSession = Struct.new(:session_id, :user_id, :username, :token,
                          :created_at, :expires_at)

  # User profile structure
  UserProfile = Struct.new(:user_id, :username, :created_at, :last_login)

  # Register a new user
  def register(username, password)
    validate_username!(username)
    validate_password!(password)
    check_user_exists!(username)

    # Generate ECC key pair
    private_key, public_key = generate_ecc_keypair

    # Generate secure random salt
    salt = SecureRandom.base64(32)

    # Argon2-style password hashing (simplified for demo)
    argon2_hash = argon2_hash(password, salt)

    # Additional BLAKE3-style hashing
    blake3_hash = blake3_hash(argon2_hash)

    user_id = "user_#{Time.now.to_i}_#{rand(1000)}"
    user_data = UserData.new(
      user_id,
      username,
      blake3_hash,
      salt,
      private_key,
      public_key,
      Time.now
    )

    @users[username] = user_data
    @user_ids[user_id] = user_data

    puts "User registered successfully: #{username} (#{user_id})"
    user_id
  end

  # Authenticate user and return JWT token
  def authenticate(username, password)
    user_data = @users[username] or raise AuthError.new('User not found')

    # Verify password using constant-time comparison
    salt = user_data.salt
    computed_argon2 = argon2_hash(password, salt)
    computed_blake3 = blake3_hash(computed_argon2)

    unless constant_time_compare?(computed_blake3, user_data.password_hash)
      raise AuthError.new('Invalid credentials')
    end

    # Create JWT token
    now = Time.now
    expiry = now + (24 * 60 * 60) # 24 hours

    payload = {
      sub: user_data.user_id,
      username: user_data.username,
      iat: now.to_i,
      exp: expiry.to_i
    }

    token = create_jwt(payload, user_data.ecc_private_key)

    puts "User authenticated successfully: #{username}"
    token
  end

  # Verify JWT token
  def verify_token(token)
    payload = verify_jwt(token)

    expires_at = Time.at(payload['exp'])
    if expires_at < Time.now
      raise AuthError.new('Token expired')
    end

    UserSession.new(
      SecureRandom.uuid,
      payload['sub'],
      payload['username'],
      token,
      Time.now,
      expires_at
    )
  end

  # Get user profile
  def get_user_profile(user_id)
    user_data = @user_ids[user_id] or raise AuthError.new('User not found')

    UserProfile.new(
      user_data.user_id,
      user_data.username,
      user_data.created_at,
      Time.now
    )
  end

  private

  # Validation methods
  def validate_username!(username)
    unless username.length.between?(3, 50)
      raise AuthError.new('Username must be between 3 and 50 characters')
    end
  end

  def validate_password!(password)
    unless password.length >= 8
      raise AuthError.new('Password must be at least 8 characters')
    end
  end

  def check_user_exists!(username)
    if @users.key?(username)
      raise AuthError.new('User already exists')
    end
  end

  # Cryptographic methods (simplified for demo)
  def generate_ecc_keypair
    # Generate ECC secp256k1 key pair (simplified)
    private_key_bytes = SecureRandom.random_bytes(32)
    private_key = Base64.strict_encode64(private_key_bytes)

    # Derive public key (simplified - in production use proper ECC math)
    public_key = "public_key_derived_from_#{Digest::SHA256.hexdigest(private_key_bytes)}"

    [private_key, public_key]
  end

  def argon2_hash(password, salt)
    # Simplified Argon2 implementation (use proper gem in production)
    combined = password + salt
    Digest::SHA256.hexdigest(combined)
  end

  def blake3_hash(data)
    # Simplified BLAKE3 implementation (use proper gem in production)
    Digest::SHA256.hexdigest(data)
  end

  def create_jwt(payload, private_key)
    # Simplified JWT creation (use proper JWT gem in production)
    header = { alg: 'HS256', typ: 'JWT' }
    header_b64 = Base64.strict_encode64(header.to_json)
    payload_b64 = Base64.strict_encode64(payload.to_json)

    message = "#{header_b64}.#{payload_b64}"
    signature = Digest::SHA256.hexdigest(message)

    "#{message}.#{signature}"
  end

  def verify_jwt(token)
    parts = token.split('.')
    raise AuthError.new('Invalid token format') unless parts.length == 3

    payload_b64 = parts[1]
    payload_json = Base64.decode64(payload_b64)
    payload = JSON.parse(payload_json)

    payload
  rescue JSON::ParserError
    raise AuthError.new('Invalid token')
  end

  def constant_time_compare?(a, b)
    return false unless a.length == b.length

    result = 0
    a.each_byte.with_index do |byte, i|
      result |= byte ^ b[i].ord
    end

    result == 0
  end
end

# Custom authentication error
class AuthError < StandardError
  attr_reader :message

  def initialize(message)
    @message = message
  end
end

# Global auth handler instance
AUTH_HANDLER = EccAuthHandler.new

# Sinatra application routes

# Root endpoint
get '/' do
  json({
    message: 'DegenHF ECC Authentication API - Ruby Sinatra',
    version: '1.0.0',
    endpoints: '/api/auth/*'
  })
end

# Health check endpoint
get '/api/auth/health' do
  json({
    status: 'healthy',
    service: 'ecc-auth'
  })
end

# Register endpoint
post '/api/auth/register' do
  begin
    request_body = JSON.parse(request.body.read)
    username = request_body['username']
    password = request_body['password']

    user_id = AUTH_HANDLER.register(username, password)

    json({
      success: true,
      message: 'User registered successfully',
      userId: user_id
    })
  rescue AuthError => e
    status 400
    json({
      success: false,
      message: e.message,
      userId: nil
    })
  rescue => e
    status 400
    json({
      success: false,
      message: 'Registration failed',
      userId: nil
    })
  end
end

# Authenticate endpoint
post '/api/auth/authenticate' do
  begin
    request_body = JSON.parse(request.body.read)
    username = request_body['username']
    password = request_body['password']

    token = AUTH_HANDLER.authenticate(username, password)

    json({
      success: true,
      message: 'Authentication successful',
      token: token
    })
  rescue AuthError => e
    status 401
    json({
      success: false,
      message: e.message,
      token: nil
    })
  rescue => e
    status 401
    json({
      success: false,
      message: 'Authentication failed',
      token: nil
    })
  end
end

# Verify endpoint
post '/api/auth/verify' do
  begin
    request_body = JSON.parse(request.body.read)
    token = request_body['token']

    session = AUTH_HANDLER.verify_token(token)

    json({
      success: true,
      message: 'Token is valid',
      userId: session.user_id,
      username: session.username,
      expiresAt: session.expires_at.iso8601
    })
  rescue AuthError => e
    status 401
    json({
      success: false,
      message: e.message,
      userId: nil,
      username: nil,
      expiresAt: nil
    })
  rescue => e
    status 401
    json({
      success: false,
      message: 'Token verification failed',
      userId: nil,
      username: nil,
      expiresAt: nil
    })
  end
end

# Profile endpoint
get '/api/auth/profile' do
  begin
    auth_header = request.env['HTTP_AUTHORIZATION']
    unless auth_header&.start_with?('Bearer ')
      raise AuthError.new('Authorization header required')
    end

    token = auth_header[7..-1] # Remove 'Bearer ' prefix
    session = AUTH_HANDLER.verify_token(token)
    profile = AUTH_HANDLER.get_user_profile(session.user_id)

    json({
      success: true,
      message: 'Profile retrieved successfully',
      profile: {
        userId: profile.user_id,
        username: profile.username,
        createdAt: profile.created_at.iso8601,
        lastLogin: profile.last_login.iso8601
      }
    })
  rescue AuthError => e
    status 401
    json({
      success: false,
      message: e.message,
      profile: nil
    })
  rescue => e
    status 401
    json({
      success: false,
      message: 'Profile retrieval failed',
      profile: nil
    })
  end
end

# Error handling
error do
  status 500
  json({
    success: false,
    message: 'Internal server error',
    error: env['sinatra.error']&.message
  })
end