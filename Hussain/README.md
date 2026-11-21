# Kaamkaaj Python backend

The API uses FastAPI and a local SQLite database. It supports user and worker
registration/login, logout, authenticated booking creation, and contact form
submissions. New bookings remain pending until a worker accepts them; the
booking page redirects customers to a live status page. Pending bookings expire
after two minutes if no worker accepts, and the customer is told to try again
later. A property type is required to submit a booking.
After a worker accepts, the booking status endpoint returns that worker's name
phone number, and service area to the user who created the booking. Worker
service areas are shared with customers; workers' residential addresses are
not collected or returned.

Workers can retrieve pending bookings at `GET /worker/service-requests` and
accept one with `POST /worker/service-requests/{id}/accept`. Include the
worker's session cookie and the CSRF token returned by `GET /auth/me`. The
worker dashboard displays incoming bookings and increments its completed-jobs
count after a successful acceptance. `GET /worker/activity` returns that
worker's accepted bookings, newest first; the dashboard shows each booking's
services, customer, acceptance time, and reference. Pending booking records
include the customer's name, email, phone, and service address; they are visible
only to authenticated worker accounts. Users provide an address in their profile or
when booking, and that address is saved to their profile and copied into each
booking. Workers enter a service area during registration or update it with
`POST /worker/service-area`; the customer sees it only after that worker
accepts their booking. `GET /worker/stats` returns the number of bookings
accepted today for the supplied local date and timezone offset.
Users can cancel a pending booking with `POST /service-requests/{id}/cancel`;
the user session cookie and CSRF token are required.

## Setup

From this directory, install the Python dependencies and start the API:

```powershell
py -m pip install -r requirements.txt
py -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

The API documentation is available at `http://127.0.0.1:8000/docs`. The SQLite
database (`kaamkaaj.db`) is created automatically next to `main.py` the first
time the server starts. Set `KAAMKAAJ_DATABASE` to use a different file.
Open the frontend at `http://127.0.0.1:8000/` so browser sessions and API
requests use the same local origin. Frontend images are served from the sibling
`images` folder automatically.
The services, packages, and booking pages require an active user login and
redirect signed-out visitors to the login page while preserving the requested
page for after login. The worker homepage is restricted to worker accounts and
displays the worker name from the authenticated session.

For HTTPS deployments, set `KAAMKAAJ_COOKIE_SECURE=true` and serve the frontend
from a trusted origin.
