from eduid.webapp.support.app import support_init_app

app = support_init_app()

if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
