from eduid.webapp.bankid.app import init_bankid_app

app = init_bankid_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
