from eduid.webapp.oidc_proofing.app import init_oidc_proofing_app

name = "oidc_proofing"
app = init_oidc_proofing_app(name, {})


if __name__ == "__main__":
    app.logger.info(f"Starting {name} app...")
    app.run()
