from eduid.webapp.oidceid.app import init_oidceid_app

app = init_oidceid_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
