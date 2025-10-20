Rails.application.routes.draw do
  # Health check
  get '/health', to: 'auth#health'

  # API routes
  scope '/api' do
    scope '/auth' do
      post '/register', to: 'auth#register'
      post '/login', to: 'auth#login'
      get '/verify', to: 'auth#verify'
      get '/profile', to: 'auth#profile'
    end

    # Example protected route
    get '/protected', to: 'auth#verify' # Using verify as protected route for demo
  end
end