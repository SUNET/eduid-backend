from eduid.webapp.eidas.app import init_eidas_app

app = init_eidas_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
