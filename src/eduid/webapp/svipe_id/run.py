# -*- coding: utf-8 -*-

from eduid.webapp.svipe_id.app import svipe_id_init_app

app = svipe_id_init_app()


if __name__ == "__main__":
    app.logger.info(f"Starting {app}...")
    app.run()
