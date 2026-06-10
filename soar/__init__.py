"""SOAR Pilot — Security Orchestration, Automation, and Response.

A pluggable SOAR platform: any data source can be connected through a
connector that declares its own guided integration steps. Events from every
source are normalized into a common schema, correlated into incidents, and
acted on by playbooks.
"""

from flask import Flask

from .store import Store


def create_app(seed_demo_data: bool = True) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False

    store = Store()
    if seed_demo_data:
        store.seed_demo_data()
    app.extensions["soar_store"] = store

    from .api import api_bp
    from .web import web_bp

    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(web_bp)
    return app
