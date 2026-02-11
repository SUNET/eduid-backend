from eduid.webapp.samleid.app import init_samleid_app

app = init_samleid_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
