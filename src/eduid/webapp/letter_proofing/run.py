from eduid.webapp.letter_proofing.app import init_letter_proofing_app

app = init_letter_proofing_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
