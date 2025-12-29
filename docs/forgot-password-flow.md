# Forgot Password Flow

This document describes the forgot password implementation for the Compliance Framework API.

## Overview

The forgot password flow consists of two endpoints:

1. `POST /auth/forgot-password` - Initiates password reset by sending an email
2. `POST /auth/password-reset` - Completes password reset using a JWT token

## Security Features

- **15-minute token expiry**: Password reset tokens expire after 15 minutes
- **Auth method validation**: Only users with `authMethod=password` can reset passwords
- **Email enumeration protection**: Same response is returned regardless of whether email exists
- **JWT token validation**: Tokens are cryptographically signed and verified
- **Token-bound email**: Password reset is performed for the email encoded in the JWT token; no separate email is accepted in the request

## Configuration

### Environment Variables

Add these to your environment or `.env` file:

```bash
# Web base URL for password reset links (required)
WEB_BASE_URL=http://localhost:3000

# Email configuration (optional but recommended)
CCF_EMAIL_ENABLED=true
CCF_EMAIL_PROVIDER=smtp
CCF_EMAIL_HOST=smtp.gmail.com
CCF_EMAIL_PORT=587
CCF_EMAIL_USERNAME=your-email@gmail.com
CCF_EMAIL_PASSWORD=your-app-password
CCF_EMAIL_FROM=your-email@gmail.com
CCF_EMAIL_FROM_NAME="Compliance Framework"
CCF_EMAIL_USE_TLS=true
```

### Email Configuration File

Create `email.yaml`:

```yaml
enabled: true
provider: "smtp"
providers:
  smtp:
    name: "SMTP"
    provider: "smtp"
    enabled: true
    host: "smtp.gmail.com"
    port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"
    from: "your-email@gmail.com"
    from_name: "Compliance Framework"
    use_tls: true
    use_ssl: false
```

## API Endpoints

### 1. Forgot Password

**Endpoint:** `POST /auth/forgot-password`

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "data": "If an account with this email exists, a password reset link has been sent."
}
```

**Behavior:**
- Validates email format
- Checks if user exists and has `authMethod=password`
- Generates a JWT token valid for 15 minutes
- Sends password reset email if email service is configured
- Returns same response regardless of user existence (security)

### 2. Password Reset

**Endpoint:** `POST /auth/password-reset`

**Request Body:**
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "password": "newSecurePassword123"
}
```

**Response:**
```json
{
  "data": "Password has been reset successfully"
}
```

**Behavior:**
- Validates JWT token signature and expiry
- Uses email encoded in JWT token (no email field in request)
- Updates user password with bcrypt hashing
- Clears any existing reset tokens
- Requires minimum 8 character password

## Email Templates

### HTML Email Template
```html
<h2>Password Reset Request</h2>
<p>Hello {{FirstName}},</p>
<p>You requested a password reset for your Compliance Framework account.</p>
<p>Click the link below to reset your password:</p>
<p><a href="{{ResetURL}}">Reset Password</a></p>
<p>This link will expire in 15 minutes.</p>
<p>If you didn't request this password reset, you can safely ignore this email.</p>
<p>Thank you,<br/>Compliance Framework Team</p>
```

### Text Email Template
```
Password Reset Request

Hello {{FirstName}},

You requested a password reset for your Compliance Framework account.
Visit the following link to reset your password:
{{ResetURL}}

This link will expire in 15 minutes.

If you didn't request this password reset, you can safely ignore this email.

Thank you,
Compliance Framework Team
```

## Frontend Integration

### Password Reset Form

Your frontend should:

1. Collect email from user
2. Call `POST /auth/forgot-password`
3. Show success message regardless of result
4. When user clicks email link, extract token from URL query parameter
5. Show password reset form with token and email fields
6. Call `POST /auth/password-reset` with new password
7. Redirect to login on success

### Example URL Format
```
http://localhost:3000/reset-password?token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
```

## Error Handling

### Common Error Responses

**400 Bad Request:**
```json
{
  "error": "invalid email format"
}
```

**401 Unauthorized:**
```json
{
  "error": "invalid or expired token"
}
```

**404 Not Found:**
```json
{
  "error": "user not found"
}
```

**500 Internal Server Error:**
```json
{
  "error": "failed to generate password reset token"
}
```

## Testing

Run the forgot password tests:

```bash
go test ./internal/api/handler/auth/ -v -run TestForgotPassword
```

## Security Considerations

1. **Rate Limiting**: Consider implementing rate limiting on forgot password endpoint
2. **Email Security**: Ensure email service is properly secured with TLS
3. **Token Storage**: Tokens are not stored in database (stateless JWT)
4. **Password Policy**: Enforce strong password requirements
5. **Logging**: All password reset attempts are logged for security monitoring
6. **Account Lockout**: Consider implementing account lockout after failed attempts

## Troubleshooting

### Email Not Sending
- Check email service configuration
- Verify SMTP credentials and connectivity
- Check application logs for email errors
- Ensure `CCF_EMAIL_ENABLED=true`

### Token Invalid/Expired
- Tokens expire after 15 minutes
- Check system time synchronization
- Verify JWT public/private key configuration

### User Cannot Reset Password
- Verify user has `authMethod=password`
- Check if user account is active
- Verify email exists in database
