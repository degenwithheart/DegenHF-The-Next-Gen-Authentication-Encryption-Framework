# Sample Authentication Widget Blueprint

This is a sample Blueprint widget that demonstrates how to integrate DegenHF authentication into your Unreal Engine UI.

## Setup Instructions

1. Create a new User Widget Blueprint called `WB_Authentication`
2. Add the following UI elements:
   - Text Block (Title): "DegenHF Authentication"
   - Editable Text Box (Username Input)
   - Editable Text Box (Password Input) - Set Is Password to true
   - Button (Register Button)
   - Button (Login Button)
   - Text Block (Status Text)

3. In the Widget Blueprint Graph, add the following logic:

### Register Button Logic
```
Username Input → Get Text → Register User (DegenHF) → Branch
├── True → Set Status Text: "Registration Successful!"
└── False → Set Status Text: "Registration Failed"
```

### Login Button Logic
```
Username Input → Get Text → Authenticate User (DegenHF) → Branch
├── True → Set Status Text: "Login Successful!" → Open Main Menu
└── False → Set Status Text: "Login Failed"
```

## Blueprint Function Usage

### Register User
- **Inputs**: Username (String), Password (String)
- **Outputs**: UserId (String), Success (Boolean)
- **Description**: Creates a new user account with ECC-secured password

### Authenticate User
- **Inputs**: Username (String), Password (String)
- **Outputs**: Token (String), Success (Boolean)
- **Description**: Verifies credentials and returns JWT token

### Verify Token
- **Inputs**: Token (String)
- **Outputs**: UserId (String), Username (String), IsValid (Boolean)
- **Description**: Validates JWT token and extracts user information

## Advanced Features

### Auto-Login
Add this to your Game Instance Begin Play:
```
Is User Logged In → Branch
├── True → Get Current User ID → Load Player Data → Open Main Menu
└── False → Open Login Screen
```

### Session Persistence
Call "Save Auth Data" when the game closes and "Load Auth Data" when it starts.

## Error Handling

Always check the Success output from authentication functions and provide user-friendly error messages:

- Empty username/password
- Network connectivity issues
- Invalid credentials
- Token expiration

## Security Notes

- Never log passwords or tokens
- Clear sensitive data from memory when not needed
- Use HTTPS for server communication
- Implement proper session timeouts