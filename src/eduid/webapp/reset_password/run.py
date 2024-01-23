from eduid.webapp.reset_password.app import init_reset_password_app

app = init_reset_password_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app} app...")
    app.run()
