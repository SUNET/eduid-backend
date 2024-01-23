from eduid.webapp.lookup_mobile_proofing.app import init_lookup_mobile_proofing_app

app = init_lookup_mobile_proofing_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
