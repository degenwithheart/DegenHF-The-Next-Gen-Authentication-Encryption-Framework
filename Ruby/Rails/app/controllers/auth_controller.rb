require 'degenhf/ecc_auth_handler'

class AuthController < ApplicationController
  skip_before_action :verify_authenticity_token
  before_action :initialize_auth_handler

  # GET /health
  def health
    render json: {
      status: 'healthy',
      service: 'degenhf-rails',
      timestamp: Time.now.to_i
    }
  end

  # POST /api/auth/register
  def register
    begin
      params.require(%i[username password])

      if params[:username].blank?
        return render json: { error: 'Invalid input', message: 'Username cannot be empty' }, status: :bad_request
      end

      if params[:password].length < 8
        return render json: { error: 'Invalid input', message: 'Password must be at least 8 characters' }, status: :bad_request
      end

      user_id = @auth_handler.register(params[:username], params[:password])
      render json: {
        user_id: user_id,
        message: 'User registered successfully'
      }, status: :created

      Rails.logger.info("User registered: #{params[:username]}")

    rescue => e
      Rails.logger.error("Registration failed: #{e.message}")
      render json: {
        error: 'Registration failed',
        message: e.message
      }, status: :bad_request
    end
  end

  # POST /api/auth/login
  def login
    begin
      params.require(%i[username password])

      if params[:username].blank? || params[:password].blank?
        return render json: { error: 'Invalid input', message: 'Username and password are required' }, status: :bad_request
      end

      token = @auth_handler.authenticate(params[:username], params[:password])
      render json: {
        token: token,
        message: 'Login successful'
      }, status: :ok

      Rails.logger.info("User logged in: #{params[:username]}")

    rescue => e
      Rails.logger.error("Login failed: #{e.message}")
      render json: {
        error: 'Authentication failed',
        message: e.message
      }, status: :unauthorized
    end
  end

  # GET /api/auth/verify
  def verify
    begin
      auth_header = request.headers['Authorization']
      unless auth_header&.start_with?('Bearer ')
        return render json: { error: 'Missing token', message: 'Authorization header with Bearer token required' }, status: :unauthorized
      end

      token = auth_header.sub('Bearer ', '')
      session = @auth_handler.verify_token(token)

      render json: {
        user_id: session[:user_id],
        username: session[:username],
        message: 'Token is valid'
      }, status: :ok

      Rails.logger.debug("Token verified for user: #{session[:username]}")

    rescue => e
      Rails.logger.error("Token verification failed: #{e.message}")
      render json: {
        error: 'Token verification failed',
        message: e.message
      }, status: :unauthorized
    end
  end

  # GET /api/auth/profile
  def profile
    begin
      auth_header = request.headers['Authorization']
      unless auth_header&.start_with?('Bearer ')
        return render json: { error: 'Missing token', message: 'Authorization header with Bearer token required' }, status: :unauthorized
      end

      token = auth_header.sub('Bearer ', '')
      session = @auth_handler.verify_token(token)

      profile = @auth_handler.get_user_profile(session[:user_id])
      render json: {
        user_id: profile[:user_id],
        username: profile[:username],
        profile: {
          created_at: profile[:created_at].iso8601,
          last_login: profile[:last_login].iso8601
        }
      }, status: :ok

      Rails.logger.debug("Profile retrieved for user: #{profile[:username]}")

    rescue => e
      Rails.logger.error("Profile retrieval failed: #{e.message}")
      render json: {
        error: 'Profile retrieval failed',
        message: e.message
      }, status: :internal_server_error
    end
  end

  private

  def initialize_auth_handler
    @auth_handler ||= DegenHF::EccAuthHandler.new(
      hash_iterations: 100_000,
      token_expiry: 86_400, # 24 hours
      cache_size: 10_000,
      cache_ttl: 300, # 5 minutes
      logger: Rails.logger
    )
  end
end