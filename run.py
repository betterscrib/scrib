#! /usr/bin/env python
#from fapp import app
from flask_bootstrap import Bootstrap
from flask import Flask
import logging as lg



def create_app():
    app = Flask(__name__)
    Bootstrap(app)
    app.config.from_object('config')

    from fapp.models import db
    db.init_app(app)

    from fapp.models import login_manager
    login_manager.init_app(app)

    from fapp.views import main_bp
    app.register_blueprint(main_bp)

    return app

def init_db(app):
    from fapp.models import db
    with app.app_context():
        db.drop_all()
        db.create_all()
        db.session.commit()
    lg.warning('Database initialized!')


if __name__ == "__main__":
    app = create_app()
    init_db(app)
    app.run(debug=True)