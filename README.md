# Winning Edge Investment Platform

A Node.js based investment and user management portal.

## Features

- **User Authentication**: Signup, Login, and Two-Factor Authentication (2FA).
- **Admin Dashboard**: Manage users, investments, deposits, withdrawals, and settings.
- **User Dashboard**: View portfolio, make investments, request withdrawals, and contact support.
- **Financial Operations**: Automated handling of investment maturity and transaction tracking.
- **Support System**: Integrated ticketing system for user support.

## Prerequisites

- Node.js
- MySQL

## Setup

1.  **Install dependencies:**
    ```bash
    npm install
    ```

2.  **Configure Environment:**
    Create a `.env` file in the root directory. You can use the variables found in `server.js` as a template (e.g., `DB_HOST`, `DB_USER`, `SMTP_USER`, etc.).

3.  **Database Setup:**
    Ensure your MySQL database (`user_portal_db`) is running and the necessary tables are created.

4.  **Run the server:**
    ```bash
    node server.js
    ```