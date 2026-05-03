- github-repo: git@tanya:vankayalapatitanya-gif/jwks-server-project.git
- user.name: vankayalapatitanya-gif
- user.email: vankayalapatitanya5@gmail.com

# Enhancing security and user management in the JWKS Server

## Objective

To further enhance the security and functionality of your JWKS server by implementing AES encryption for private keys, adding user registration capabilities, logging authentication requests, and optionally introducing a rate limiter to control request frequency.

## Background

As cybersecurity threats evolve, it's crucial to continuously improve the security and robustness of authentication systems. This project focuses on adding layers of security to the JWKS server by encrypting sensitive data, managing user registrations, and monitoring authentication requests. Additionally, implementing the optional rate limiter can prevent abuse and protect the server from potential DoS attacks.

> Note: In a "real system", you would also include a random initialization vector (IV) for each encryption, and since the IV is not considered confidential, it can be kept in a separate column in the same table.  The IV's primary purpose is to provide variability and unpredictability to the encryption process.

## Requirements

### AES Encryption of Private Keys

- Encrypt private keys in the database using symmetric AES encryption.
- Use a key provided from the environment variable named NOT_MY_KEY for encryption and decryption.
- Ensure that the encryption process is secure and that that key is never exposed. NEVER COMMIT SECRETS.

### User Registration

Create a users table in the database with appropriate fields for storing user information and hashed passwords with this schema:

```sql
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
)
```

Implement a POST:/register endpoint that:

- Accepts user registration details in request body using this JSON format:

```json
{"username": "$MyCoolUsername", "email": "$MyCoolEmail"}
```

- Generates a secure password for the user using UUIDv4Links to an external site..
- Returns the password to the user in this JSON format:

```json
{"password": "$UUIDv4"}.
```

- Returned HTTP status code should be either OKLinks to an external site., or CREATEDLinks to an external site..
- Hashes the password using the secure password hashing algorithm Argon2 with the configurable settings (time, memory, parallelism, key length, and salt) up to you.
- Stores the user details and hashed password in the users table.

### Logging Authentication Requests

Create a database table auth_logs to log authentication requests with the following schema:

```sql
CREATE TABLE IF NOT EXISTS auth_logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_ip TEXT NOT NULL,
    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

For each POST:/auth request, log the following details into the DB table auth_logs:

- Request IP address.
- Timestamp of the request.
- User ID of the username.

### Rate Limiter (Optional)

- Implement a time-window rate limiterLinks to an external site. for the POST:/auth endpoint.
- Limit requests to 10 requests per second.
- Requests over that limit should return a 429 Too Many Requests (RFC 6585Links to an external site.).
- Only requests that succeed should be logged to the authentication logging table.

## Expected Outcome

By the end of the project, your JWKS server should have enhanced security through AES encryption, the ability to register users and store their hashed passwords, a logging mechanism for authentication requests, and an optional rate limiter to control request frequency.

This project should take 2-12 hours, depending on your familiarity with your chosen language/framework and encryption in general, and the structure of your previous code.

## Deliverables

- Provide a link to your GitHub repo containing your code.
- Include in the repo a screenshot of the Gradebot test clientLinks to an external site. running against your server.
- Include in the repo a screenshot of your test suite (if present) showing the coverage percent.
- As always with every screenshot, please include identifying information.

## Some Rubric

Some Rubric

Criteria	Ratings	Points

### Private keys are encrypted

- view longer description
- Full Marks
- 25 pts
- No Marks
- 0 pts
- /25 pts

### Create users table

- view longer description
- Full Marks
- 5 pts
- No Marks
- 0 pts
- /5 pts

### /register endpoint

- view longer description
- Full Marks
- 20 pts
- No Marks
- 0 pts
- /20 pts

### Create auth_logs table

- view longer description
- Full Marks
- 5 pts
- No Marks
- 0 pts
- /5 pts

### /auth requests are logged

- Full Marks
- 10 pts
- No Marks
- 0 pts
- /10 pts

### /auth is rate-limited (optional)

- view longer description
- Full Marks
- 25 pts
- No Marks
- 0 pts
- /25 pts

### Testsuite is present

- view longer description
- Full Marks
- 15 pts
- No Marks
- 0 pts
- /15 pts

### Test coverage

- view longer description
- Full Marks
- 5 pts
- No Marks
- 0 pts
- /5 pts

### Documentation/Linting/Organization

- view longer description
- Full Marks
- 15 pts
- No Marks
- 0 pts
- /15 pts
