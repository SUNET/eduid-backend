from eduid.webapp.authn.app import authn_init_app

app = authn_init_app()

if __name__ == "__main__":
    app.logger.info("Starting {app}...")
    app.run()
