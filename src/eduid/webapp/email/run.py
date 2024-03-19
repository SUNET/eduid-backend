from eduid.webapp.email.app import email_init_app

app = email_init_app()

if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
