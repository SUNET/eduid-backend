from eduid.webapp.signup.app import signup_init_app

app = signup_init_app(name="signup2")

if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
