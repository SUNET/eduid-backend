from eduid.webapp.freja_eid.app import freja_eid_init_app

app = freja_eid_init_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
