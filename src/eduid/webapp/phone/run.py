from eduid.webapp.phone.app import phone_init_app

app = phone_init_app()

if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
