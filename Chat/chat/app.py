from flask import Flask, render_template
import os
from dotenv import load_dotenv, find_dotenv


load_dotenv(find_dotenv())

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")


@app.route("/")
def main_page():
    return render_template(
        "index.html"
    )


if __name__ == "__main__":
    app.run()
