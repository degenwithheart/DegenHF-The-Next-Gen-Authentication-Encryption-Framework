require 'spec_helper'

RSpec.describe EccAuthHandler do
  let(:auth_handler) { EccAuthHandler.new }

  before(:each) do
    # Clear any existing users between tests
    auth_handler.instance_variable_set(:@users, {})
    auth_handler.instance_variable_set(:@user_ids, {})
  end

  describe '#register' do
    it 'successfully registers a new user' do
      username = "testuser_#{Time.now.to_i}"
      password = 'testpassword123'

      user_id = auth_handler.register(username, password)

      expect(user_id).to start_with('user_')
      expect(user_id).not_to be_empty
    end

    it 'raises error for duplicate username' do
      username = "duplicate_#{Time.now.to_i}"
      password = 'testpassword123'

      auth_handler.register(username, password)

      expect {
        auth_handler.register(username, 'differentpassword')
      }.to raise_error(AuthError, 'User already exists')
    end

    it 'raises error for short password' do
      username = "testuser_#{Time.now.to_i}"
      password = 'short'

      expect {
        auth_handler.register(username, password)
      }.to raise_error(AuthError, 'Password must be at least 8 characters')
    end

    it 'raises error for invalid username' do
      username = 'ab' # Too short
      password = 'testpassword123'

      expect {
        auth_handler.register(username, password)
      }.to raise_error(AuthError, 'Username must be between 3 and 50 characters')
    end
  end

  describe '#authenticate' do
    it 'successfully authenticates with correct credentials' do
      username = "authuser_#{Time.now.to_i}"
      password = 'testpassword123'

      auth_handler.register(username, password)
      token = auth_handler.authenticate(username, password)

      expect(token).not_to be_empty
      expect(token.split('.').length).to eq(3)
    end

    it 'raises error for wrong password' do
      username = "authuser_#{Time.now.to_i}"
      password = 'testpassword123'

      auth_handler.register(username, password)

      expect {
        auth_handler.authenticate(username, 'wrongpassword')
      }.to raise_error(AuthError, 'Invalid credentials')
    end

    it 'raises error for non-existent user' do
      expect {
        auth_handler.authenticate('nonexistent', 'password')
      }.to raise_error(AuthError, 'User not found')
    end
  end

  describe '#verify_token' do
    it 'successfully verifies a valid token' do
      username = "verifyuser_#{Time.now.to_i}"
      password = 'testpassword123'

      auth_handler.register(username, password)
      token = auth_handler.authenticate(username, password)
      session = auth_handler.verify_token(token)

      expect(session.username).to eq(username)
      expect(session.expires_at).to be > Time.now
    end

    it 'raises error for invalid token' do
      expect {
        auth_handler.verify_token('invalid.token.here')
      }.to raise_error(AuthError)
    end
  end

  describe '#get_user_profile' do
    it 'successfully retrieves user profile' do
      username = "profileuser_#{Time.now.to_i}"
      password = 'testpassword123'

      user_id = auth_handler.register(username, password)
      profile = auth_handler.get_user_profile(user_id)

      expect(profile.user_id).to eq(user_id)
      expect(profile.username).to eq(username)
    end

    it 'raises error for non-existent user' do
      expect {
        auth_handler.get_user_profile('invalid_user_id')
      }.to raise_error(AuthError, 'User not found')
    end
  end
end

RSpec.describe 'Sinatra App' do
  include Rack::Test::Methods

  def app
    Sinatra::Application
  end

  describe 'GET /' do
    it 'returns welcome message' do
      get '/'

      expect(last_response).to be_ok
      response_body = JSON.parse(last_response.body)
      expect(response_body['message']).to include('DegenHF ECC Authentication API')
    end
  end

  describe 'GET /api/auth/health' do
    it 'returns health status' do
      get '/api/auth/health'

      expect(last_response).to be_ok
      response_body = JSON.parse(last_response.body)
      expect(response_body['status']).to eq('healthy')
      expect(response_body['service']).to eq('ecc-auth')
    end
  end

  describe 'POST /api/auth/register' do
    it 'successfully registers a user' do
      username = "testuser_#{Time.now.to_i}"
      request_body = {
        username: username,
        password: 'testpassword123'
      }.to_json

      post '/api/auth/register', request_body, { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response).to be_ok
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be true
      expect(response_body['userId']).to start_with('user_')
    end

    it 'returns error for invalid data' do
      request_body = {
        username: '',
        password: 'short'
      }.to_json

      post '/api/auth/register', request_body, { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response.status).to eq(400)
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be false
    end
  end

  describe 'POST /api/auth/authenticate' do
    it 'successfully authenticates a user' do
      # First register the user
      username = "authuser_#{Time.now.to_i}"
      register_body = {
        username: username,
        password: 'testpassword123'
      }.to_json

      post '/api/auth/register', register_body, { 'CONTENT_TYPE' => 'application/json' }

      # Then authenticate
      auth_body = {
        username: username,
        password: 'testpassword123'
      }.to_json

      post '/api/auth/authenticate', auth_body, { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response).to be_ok
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be true
      expect(response_body['token']).not_to be_empty
    end

    it 'returns error for wrong credentials' do
      auth_body = {
        username: 'nonexistent',
        password: 'wrongpassword'
      }.to_json

      post '/api/auth/authenticate', auth_body, { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response.status).to eq(401)
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be false
    end
  end

  describe 'POST /api/auth/verify' do
    it 'successfully verifies a token' do
      # Register and authenticate to get token
      username = "verifyuser_#{Time.now.to_i}"
      register_body = {
        username: username,
        password: 'testpassword123'
      }.to_json

      post '/api/auth/register', register_body, { 'CONTENT_TYPE' => 'application/json' }

      auth_body = {
        username: username,
        password: 'testpassword123'
      }.to_json

      post '/api/auth/authenticate', auth_body, { 'CONTENT_TYPE' => 'application/json' }
      auth_response = JSON.parse(last_response.body)
      token = auth_response['token']

      # Verify token
      verify_body = { token: token }.to_json
      post '/api/auth/verify', verify_body, { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response).to be_ok
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be true
      expect(response_body['username']).to eq(username)
    end

    it 'returns error for invalid token' do
      verify_body = { token: 'invalid.token' }.to_json
      post '/api/auth/verify', verify_body, { 'CONTENT_TYPE' => 'application/json' }

      expect(last_response.status).to eq(401)
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be false
    end
  end

  describe 'GET /api/auth/profile' do
    it 'successfully retrieves user profile' do
      # Register and authenticate to get token
      username = "profileuser_#{Time.now.to_i}"
      register_body = {
        username: username,
        password: 'testpassword123'
      }.to_json

      post '/api/auth/register', register_body, { 'CONTENT_TYPE' => 'application/json' }

      auth_body = {
        username: username,
        password: 'testpassword123'
      }.to_json

      post '/api/auth/authenticate', auth_body, { 'CONTENT_TYPE' => 'application/json' }
      auth_response = JSON.parse(last_response.body)
      token = auth_response['token']

      # Get profile
      get '/api/auth/profile', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{token}" }

      expect(last_response).to be_ok
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be true
      expect(response_body['profile']['username']).to eq(username)
    end

    it 'returns error without authorization header' do
      get '/api/auth/profile'

      expect(last_response.status).to eq(401)
      response_body = JSON.parse(last_response.body)
      expect(response_body['success']).to be false
    end
  end
end