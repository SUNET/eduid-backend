from eduid.webapp.group_management.app import init_group_management_app

app = init_group_management_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
