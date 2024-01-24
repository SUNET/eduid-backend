from eduid.webapp.personal_data.app import pd_init_app

app = pd_init_app()

if __name__ == "__main__":
    app.logger.info(f"Starting {app} app...")
    app.run()
