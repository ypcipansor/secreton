from playwright.sync_api import sync_playwright, Page, expect
import time

def run(playwright):
    browser = playwright.chromium.launch(headless=True)
    context = browser.new_context()
    page = context.new_page()

    # Log console messages
    page.on("console", lambda msg: print(f"Console: {msg.text}"))
    page.on("pageerror", lambda msg: print(f"PageError: {msg}"))
    page.on("requestfailed", lambda request: print(f"Request failed: {request.url} {request.failure}"))

    # Mock API responses
    def handle_login(route):
        print(f"Intercepted login: {route.request.url}")
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"success": true, "data": {"access_token": "fake-jwt-token", "user": {"id": "1", "username": "admin", "email": "admin@example.com", "roles": ["admin"], "permissions": [], "metadata": {}, "last_login": null}, "mfa_required": false}}'
        )

    def handle_health(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"success": true, "data": {"status": "healthy", "version": "0.1.0"}}'
        )

    def handle_secrets(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body='{"success": true, "data": {"my-secret": "top-secret-value"}}'
        )

    page.route("**/api/v1/auth/login", handle_login)
    page.route("**/api/v1/sys/health", handle_health)
    page.route("**/api/v1/secrets/data**", handle_secrets)

    # 1. Load Page (expect redirect to login)
    print("Navigating to home...")
    page.goto("http://localhost:8081/")

    # Wait for loading to finish/redirect
    # Expect Login page
    print("Waiting for login page...")
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible(timeout=30000)

    page.screenshot(path="verification/1_login_page.png")
    print("Login page screenshot taken.")

    # 2. Perform Login
    page.fill("input[name='username']", "admin")
    page.fill("input[name='password']", "password")
    print("Submitting login form...")
    page.click("button[type='submit']")

    # 3. Expect Dashboard
    print("Waiting for dashboard...")
    try:
        expect(page.get_by_role("heading", name="Dashboard")).to_be_visible(timeout=10000)
        expect(page.get_by_text("healthy")).to_be_visible()

        page.screenshot(path="verification/2_dashboard.png")
        print("Dashboard screenshot taken.")
    except Exception as e:
        print(f"Dashboard verification failed: {e}")
        page.screenshot(path="verification/failure_dashboard.png")
        if page.get_by_role("heading", name="Sign in").is_visible():
            print("Still on login page.")
        raise e

    # 4. Navigate to Secrets
    print("Navigating to secrets...")
    page.click("a[href='/secrets']")

    expect(page.get_by_role("heading", name="Secrets")).to_be_visible()
    # Expect data content from mock
    expect(page.get_by_text("my-secret")).to_be_visible()
    expect(page.get_by_text("top-secret-value")).to_be_visible()

    page.screenshot(path="verification/3_secrets.png")
    print("Secrets screenshot taken.")

    browser.close()

with sync_playwright() as playwright:
    run(playwright)
