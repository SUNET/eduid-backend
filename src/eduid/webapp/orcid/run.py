from eduid.webapp.orcid.app import init_orcid_app

app = init_orcid_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
