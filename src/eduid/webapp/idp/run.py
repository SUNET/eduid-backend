from eduid.webapp.idp.app import init_idp_app

app = init_idp_app()

if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
