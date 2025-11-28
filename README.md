# Secure Cloud Storage

A cloud storage prototype that incorporates encryption and access control mechanisms to ensure data security.

## 🔒 Security Features

### 1. Data Encryption
- **AES-256-CBC Encryption**: All files are encrypted using AES-256-CBC algorithm before being stored on disk
- **Random IV Generation**: Each file encryption uses a unique randomly generated Initialization Vector (IV)
- **File Hash Verification**: SHA-256 hash is generated for each file to ensure data integrity

### 2. Authentication
- **JWT-Based Authentication**: Secure JSON Web Token based user authentication
- **Password Hashing**: User passwords are hashed using bcrypt with salt rounds
- **Strong Password Policy**: Passwords must contain uppercase, lowercase, numbers, and special characters

### 3. Access Control
- **Role-Based Access Control (RBAC)**: Users can have 'user' or 'admin' roles
- **File Permissions**: Three permission levels - read, write, admin
- **Permission Expiration**: Time-limited access grants for shared files
- **Owner-Only Operations**: Certain operations (delete, share) restricted to file owners

### 4. Secure File Sharing
- **User-to-User Sharing**: Share files with specific users with defined permission levels
- **Password-Protected Links**: Share links can require password authentication
- **Download Limits**: Share links can have maximum download limits
- **Expiring Links**: Share links can have expiration dates

### 5. Security Headers & Rate Limiting
- **Helmet.js**: Security headers including CSP, XSS protection
- **CORS Configuration**: Configurable Cross-Origin Resource Sharing
- **Rate Limiting**: Protection against brute force attacks

### 6. Audit Logging
- **Comprehensive Logging**: All actions are logged with timestamps, IP addresses, and user agents
- **Security Events**: Failed login attempts, unauthorized access attempts are tracked

## 🚀 Getting Started

### Prerequisites
- Node.js v18 or higher
- npm v8 or higher

### Installation

1. Clone the repository:
```bash
git clone https://github.com/your-repo/cloud-storage.git
cd cloud-storage
```

2. Install dependencies:
```bash
npm install
```

3. Create environment configuration:
```bash
cp .env.example .env
```

4. Edit `.env` with your configuration:
```env
# Generate a strong JWT secret
JWT_SECRET=your-super-secret-jwt-key-change-in-production

# Generate a 32-character encryption key
ENCRYPTION_KEY=your-32-character-encryption-key!
```

5. Start the server:
```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm start
```

6. Access the application at `http://localhost:3000`

### Running Tests
```bash
npm test
```

## 📚 API Documentation

### Authentication

#### Register
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePass123!"
}
```

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

#### Get Profile
```http
GET /api/auth/profile
Authorization: Bearer <token>
```

### File Operations

#### Upload File
```http
POST /api/files/upload
Authorization: Bearer <token>
Content-Type: multipart/form-data

file: <binary file data>
```

#### List Files
```http
GET /api/files
Authorization: Bearer <token>
```

#### Get File Details
```http
GET /api/files/:uuid
Authorization: Bearer <token>
```

#### Download File
```http
GET /api/files/:uuid/download
Authorization: Bearer <token>
```

#### Delete File
```http
DELETE /api/files/:uuid
Authorization: Bearer <token>
```

### File Sharing

#### Share with User
```http
POST /api/files/:uuid/share
Authorization: Bearer <token>
Content-Type: application/json

{
  "username": "recipient_user",
  "permission": "read"
}
```

#### Create Share Link
```http
POST /api/files/:uuid/share-link
Authorization: Bearer <token>
Content-Type: application/json

{
  "password": "optional_password",
  "maxDownloads": 10,
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

#### Access Share Link
```http
GET /api/share/:token
```

#### Download via Share Link
```http
POST /api/share/:token/download
Content-Type: application/json

{
  "password": "required_if_set"
}
```

## 🏗️ Architecture

```
├── src/
│   ├── config/          # Configuration settings
│   ├── controllers/     # Request handlers
│   ├── middleware/      # Auth, validation middleware
│   ├── models/          # Database models
│   ├── routes/          # API routes
│   ├── services/        # Business logic services
│   ├── app.js           # Express app setup
│   └── server.js        # Server entry point
├── public/              # Frontend static files
├── uploads/             # Encrypted file storage
├── data/                # SQLite database
├── tests/               # Test files
└── docs/                # Documentation
```

## 🔐 Security Best Practices

1. **Change default secrets**: Always use strong, unique values for `JWT_SECRET` and `ENCRYPTION_KEY` in production
2. **Use HTTPS**: Deploy behind a reverse proxy with SSL/TLS
3. **Regular backups**: Backup the database and encryption keys securely
4. **Monitor audit logs**: Regularly review audit logs for suspicious activity
5. **Keep dependencies updated**: Regularly update npm packages for security patches

## 📝 License

MIT License - see [LICENSE](LICENSE) for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📧 Support

For questions or issues, please open a GitHub issue.
