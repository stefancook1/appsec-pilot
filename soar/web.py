"""Web console blueprint. The UI is a single-page app driven entirely by
the REST API, so anything you can click can also be scripted."""

from flask import Blueprint, render_template

web_bp = Blueprint("web", __name__,
                   template_folder="templates", static_folder="static")


@web_bp.get("/")
def index():
    return render_template("index.html")
