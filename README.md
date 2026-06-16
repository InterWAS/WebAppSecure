# WebAppSecure

Summary of the vulnerabilities identified, the fixes applied, and how Copilot assisted in the debugging process:

- Validates user inputs by removing malicious characters and ensuring data integrity.
- Prevents users from entering potentially harmful scripts or queries.
- Implement a function that sanitizes inputs in the web form, such as username and email.
- Security adjustment: SHA-256 to hash trocar with salt and multiple iterations (PBKDF2)
- Implementing Authentication and Authorization.
- Scaffold ASP.NET Identity for user management. 
- Set Up Token-Based Authentication. 
- Generate code for issuing and validating JWT tokens in ASP.NET Core. 
- Use JWT for secure API communication. Implement Authorization: Create roles for Admin, User, and Guest in the application.
- Configure Role-Based Access Control (RBAC): Write authorization rules for different user roles in ASP.NET Core.
- Restrict access to admin features based on roles. Add authorization policies to secure specific API endpoints.
- Add endpoints for token refresh and token revocation.
- Move SigningKey to environment secret automatically (without hardcoding in appsettings).
- Ensure the application uses HTTPS for all communications. Add logging for user login and access events.
- Add correlation by RequestId to the logs to facilitate traceability between login and subsequent calls from the same session.
- Check if have test cases for user login and registration. 
- Tests for verifying role-based access to endpoints. 
- Identify and fix security vulnerabilities in authentication and authorization code.
