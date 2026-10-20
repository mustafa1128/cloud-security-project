# CloudShield Taskboard — Security & Cloud Deployment Report

**Module:** Cloud computing and cybersecurity (student project)  
**Project type:** Small public web application  
**Status:** Working starter implementation; deployment and live security tests must be completed by the student.

## 1. Executive summary
CloudShield Taskboard is a lightweight project taskboard for a fictional team. It demonstrates a basic cloud deployment path and several defensive controls: role-based access control, secure password hashing, encryption of task details at rest, CSRF protection, rate limiting, secure session-cookie attributes and browser security headers. The application is intentionally small enough to explain and demonstrate in a coursework presentation.

## 2. Scope and features
- Public landing page and login.
- One-time initial administrator setup.
- Admin can create fictional team accounts with distinct roles.
- Team dashboard lists tasks, assignees, task status and task descriptions.
- Admin, Security and Engineer can create tasks and update statuses.
- HR and Viewer have read-only access to the dashboard.
- Task descriptions are encrypted before storage in SQLite.
- Render deployment blueprint, production WSGI command and setup instructions.

## 3. Fictional team and responsibilities
| Role / fictional team member | Responsibility | System permissions |
|---|---|---|
| Project Administrator | Project lead / access owner | Create accounts; view tasks; create/update tasks |
| Leyla — Security Engineer | Threat review and security checklist | View tasks; create tasks; update statuses |
| Murad — Software Engineer | Application implementation and bug fixes | View tasks; create tasks; update statuses |
| Nigar — HR Coordinator | Team roster and role oversight | Read-only dashboard access; admin alone manages accounts |
| Samir — Viewer / QA observer | Demonstration and acceptance review | Read-only dashboard access |

This role assignment is illustrative. Accounts should be created through the administrator UI with unique passwords; no real employees or default passwords are included.

## 4. Architecture
A browser communicates over HTTPS with a Flask application served by Gunicorn. The app validates input and checks the authenticated user's role before allowing privileged actions. SQLite stores user records and task metadata; password hashes are stored instead of plaintext passwords, while task descriptions are encrypted using Fernet. On Render, environment variables hold application and encryption keys, and a persistent disk is configured for the SQLite file.

**Request flow:** Browser → HTTPS/TLS → Render web service / Gunicorn → Flask routes and RBAC → SQLite database. Task details are encrypted in the application before database insertion and decrypted only when rendered for an authenticated session.

## 5. Cryptography
### Password storage
Passwords are processed with Werkzeug's password-hashing utility. The database stores a salted password hash; it does not store the original password. Authentication checks a candidate password against that hash.

### Data encryption at rest
Task details are encrypted with Fernet from the `cryptography` package. Fernet provides authenticated symmetric encryption and uses AES-based encryption. The encryption key is supplied through `FERNET_KEY`, not stored in the database or source repository. The key must be backed up securely and kept stable: losing or replacing it makes existing encrypted task details unreadable.

### Transport encryption
The public deployment must use HTTPS, which protects traffic in transit using TLS. The application does not itself configure TLS certificates; the hosting provider terminates HTTPS. The Secure cookie setting should be enabled in the public deployment.

**Limitations:** This is a demonstration of cryptographic integration, not a full key-management system. Key rotation, access to secrets, backup encryption and recovery procedures need separate design for production.

## 6. Threats and mitigations
| Threat | Example impact | Mitigation included | Remaining concern |
|---|---|---|---|
| Password disclosure | Account takeover | Salted password hashing; no default credentials | MFA and reset process absent |
| Brute-force login | Unauthorized access | Rate limits on login/setup | Distributed attacks and account-level lockout need more work |
| Cross-site request forgery (CSRF) | A victim's browser submits unwanted changes | Flask-WTF CSRF tokens on forms | Verify every future state-changing endpoint |
| Cross-site scripting (XSS) | Script executes in a user's browser | Jinja auto-escaping and restrictive CSP | Review any future HTML/JS changes |
| Clickjacking | Site embedded in a hostile frame | `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'` | Check compatibility if embedding is ever required |
| Unauthorized privilege use | HR/viewer changes a task or manages users | Server-side role decorators | Add tests for every role/route |
| SQL injection | Database contents exposed or changed | Parameterized SQL queries | Keep parameter binding for all future queries |
| Database theft | Task descriptions exposed | Encrypted task details; password hashes | Usernames and task metadata are not encrypted |
| Key leakage | Encrypted details can be decrypted | Key supplied as an environment secret | Secret-store access and rotation remain operational responsibilities |
| Oversized requests | Resource exhaustion | 1 MB request limit and rate limiting | Hosting-level quotas and monitoring are also needed |
| Insecure browser policy | Increased impact of browser attacks | CSP and common security headers | Headers are a baseline, not a complete defense |
| Data loss | Tasks disappear after restart | Render persistent disk configuration | Confirm plan support and implement tested backups |

## 7. Cloud deployment plan
1. Store source in a private repository while developing; exclude secrets, local database and virtual environment.
2. Deploy as a Render web service using `render.yaml` and Gunicorn.
3. Set `APP_SECRET_KEY` and `FERNET_KEY` as secret environment variables.
4. Enable `COOKIE_SECURE=1` and use the HTTPS public endpoint.
5. Confirm the persistent disk is available on the chosen hosting plan; for a more scalable design use managed PostgreSQL.
6. Create the initial administrator once through `/setup`, then create the fictional team accounts.
7. Test access permissions and confirm that read-only roles cannot use task-changing endpoints.
8. Configure backups, monitoring and dependency updates before using anything beyond sample data.

## 8. Verification checklist
Record the date, deployed URL and results when you run these tests. Do not claim tests passed until you have actually performed them.

- [ ] Home page loads over HTTPS.
- [ ] `/setup` creates the first admin and no longer permits additional setup afterward.
- [ ] Valid login succeeds; invalid login fails.
- [ ] Viewer and HR cannot open `/users` or `/tasks/new`.
- [ ] Admin can create a user and select a role.
- [ ] Admin/Security/Engineer can create a task and update status.
- [ ] CSRF token removal from a POST causes rejection.
- [ ] Response includes CSP, X-Content-Type-Options and X-Frame-Options.
- [ ] Database stores a password hash rather than the plaintext password.
- [ ] Database task `details_enc` value is not readable plaintext.
- [ ] After a service restart, encrypted descriptions remain readable when the same `FERNET_KEY` is configured.
- [ ] Public deployment has `COOKIE_SECURE=1` and redirects/serves over HTTPS.

## 9. Conclusion
The project provides a practical, explainable baseline for a student cloud-security assignment. It applies defense-in-depth at the application layer and separates encryption secrets from the database. The main lesson is that security is not one feature: access control, cryptography, secure configuration, deployment, testing and ongoing operations all matter. Further work should prioritize automated authorization tests, MFA, audit logs, backups, managed database/secret storage and independent security review.

## 10. References
- Flask documentation: https://flask.palletsprojects.com/
- Flask-WTF documentation: https://flask-wtf.readthedocs.io/
- Flask-Limiter documentation: https://flask-limiter.readthedocs.io/
- Python Cryptographic Authority — cryptography / Fernet: https://cryptography.io/en/latest/fernet/
- OWASP Cheat Sheet Series: https://cheatsheetseries.owasp.org/
- Render documentation: https://render.com/docs
