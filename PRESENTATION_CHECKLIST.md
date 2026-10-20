# Demo / presentation checklist

1. Explain the fictional team and least-privilege role model.
2. Show first-time admin setup, then create Security, Engineer, HR and Viewer accounts.
3. Sign in as an Engineer and create a sample task.
4. Sign in as Viewer/HR and show the read-only dashboard.
5. Attempt to open `/users` as Viewer and show that access is denied.
6. Explain password hashing versus reversible encryption.
7. Show that the task details field in SQLite contains encrypted text (`details_enc`), not the original description.
8. Show Render environment variables without revealing their values; explain why `FERNET_KEY` must be backed up.
9. Show security headers in browser developer tools / Network tab.
10. Present the verification checklist and honestly mark only tests you actually performed.
