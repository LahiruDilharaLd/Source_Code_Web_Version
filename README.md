# Web Sever - Loan Runner

Requires Node 16.9 or newer. No npm packages needed.

## Start
    node server.js
Open http://localhost:3000

## First start
users.json is created automatically with:
- admin / admin123 (admin)
- user / user123 (user)
Change these straight away, or set ADMIN_PASSWORD before the first start:
    ADMIN_PASSWORD=MySecret node server.js

## Files
- server.js           login, sessions, admin user creation, static files
- public/index.html   the whole front end (login screen + loan runner)
- package.json
- web-sever-demo.html standalone preview with a fake login (no server needed)

Run button: each loan ID becomes https://loanplus.lk/admin#/loans/<id>/show, shown green in the terminal and opened in its own tab. Values that are not numbers only are shown in red.
