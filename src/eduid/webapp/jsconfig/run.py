from eduid.webapp.jsconfig.app import jsconfig_init_app

app = jsconfig_init_app()

if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
