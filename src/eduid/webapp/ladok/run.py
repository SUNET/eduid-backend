from eduid.webapp.ladok.app import init_ladok_app

app = init_ladok_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
