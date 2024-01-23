from eduid.webapp.security.app import security_init_app

app = security_init_app()

if __name__ == "__main__":
    app.logger.info(f"Starting {app} app...")
    app.run()
