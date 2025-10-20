require 'spec_helper'

RSpec.describe DegenHF::EccAuthHandler do
  let(:options) do
    {
      hash_iterations: 1000, # Lower for faster tests
      token_expiry: 300, # 5 minutes
      cache_size: 100,
      cache_ttl: 30, # 30 seconds
      logger: Logger.new(StringIO.new)
    }
  end
  let(:auth_handler) { DegenHF::EccAuthHandler.new(options) }

  describe '#register' do
    it 'registers a new user successfully' do
      username = 'testuser'
      password = 'testpassword123'

      user_id = auth_handler.register(username, password)

      expect(user_id).to start_with('user_')
      expect(user_id).to be_a(String)
    end

    it 'raises error for empty username' do
      expect { auth_handler.register('', 'password123') }.to raise_error(ArgumentError, 'Username cannot be empty')
    end

    it 'raises error for short password' do
      expect { auth_handler.register('username', 'short') }.to raise_error(ArgumentError, 'Password must be at least 8 characters')
    end

    it 'raises error for duplicate user' do
      username = 'testuser'
      password = 'testpassword123'

      auth_handler.register(username, password)
      expect { auth_handler.register(username, 'differentpassword') }.to raise_error(ArgumentError, 'User already exists')
    end
  end

  describe '#authenticate' do
    let(:username) { 'testuser' }
    let(:password) { 'testpassword123' }

    before do
      auth_handler.register(username, password)
    end

    it 'authenticates user and returns token' do
      token = auth_handler.authenticate(username, password)

      expect(token).to be_a(String)
      expect(token).not_to be_empty
    end

    it 'raises error for invalid credentials' do
      expect { auth_handler.authenticate(username, 'wrongpassword') }.to raise_error('Invalid credentials')
    end

    it 'raises error for non-existent user' do
      expect { auth_handler.authenticate('nonexistent', password) }.to raise_error('User not found')
    end

    it 'raises error for empty username' do
      expect { auth_handler.authenticate('', password) }.to raise_error(ArgumentError, 'Username cannot be empty')
    end

    it 'raises error for empty password' do
      expect { auth_handler.authenticate(username, '') }.to raise_error(ArgumentError, 'Password cannot be empty')
    end
  end

  describe '#verify_token' do
    let(:username) { 'testuser' }
    let(:password) { 'testpassword123' }
    let(:token) { auth_handler.authenticate(username, password) }

    before do
      auth_handler.register(username, password)
    end

    it 'verifies valid token and returns session' do
      session = auth_handler.verify_token(token)

      expect(session).to be_a(Hash)
      expect(session[:user_id]).to start_with('user_')
      expect(session[:username]).to eq(username)
    end

    it 'raises error for empty token' do
      expect { auth_handler.verify_token('') }.to raise_error(ArgumentError, 'Token cannot be empty')
    end

    it 'raises error for invalid token' do
      expect { auth_handler.verify_token('invalid.token.here') }.to raise_error(/Invalid token/)
    end
  end

  describe '#get_user_profile' do
    let(:username) { 'testuser' }
    let(:password) { 'testpassword123' }

    before do
      auth_handler.register(username, password)
    end

    it 'returns user profile' do
      user_id = auth_handler.authenticate(username, password)
      session = auth_handler.verify_token(user_id) # token is actually returned by authenticate
      profile = auth_handler.get_user_profile(session[:user_id])

      expect(profile).to be_a(Hash)
      expect(profile[:user_id]).to start_with('user_')
      expect(profile[:username]).to eq(username)
      expect(profile[:created_at]).to be_a(Time)
    end

    it 'raises error for non-existent user' do
      expect { auth_handler.get_user_profile('nonexistent') }.to raise_error('User not found')
    end
  end

  describe '#create_session' do
    let(:username) { 'testuser' }
    let(:password) { 'testpassword123' }

    before do
      auth_handler.register(username, password)
    end

    it 'creates a session for existing user' do
      user_id = auth_handler.authenticate(username, password)
      session = auth_handler.verify_token(user_id)
      new_session = auth_handler.create_session(session[:user_id])

      expect(new_session).to be_a(Hash)
      expect(new_session[:session_id]).to be_a(String)
      expect(new_session[:user_id]).to eq(session[:user_id])
    end

    it 'raises error for non-existent user' do
      expect { auth_handler.create_session('nonexistent') }.to raise_error('User not found')
    end
  end

  describe '#get_session' do
    let(:username) { 'testuser' }
    let(:password) { 'testpassword123' }

    before do
      auth_handler.register(username, password)
    end

    it 'returns valid session' do
      user_id = auth_handler.authenticate(username, password)
      session = auth_handler.verify_token(user_id)
      retrieved_session = auth_handler.create_session(session[:user_id])
      found_session = auth_handler.get_session(retrieved_session[:session_id])

      expect(found_session).to eq(retrieved_session)
    end

    it 'returns nil for non-existent session' do
      expect(auth_handler.get_session('nonexistent')).to be_nil
    end
  end
end