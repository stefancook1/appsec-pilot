"""Run the SOAR Pilot console.

    python run_soar.py            # http://127.0.0.1:8800
    PORT=9000 python run_soar.py
"""

import os

from soar import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8800))
    app.run(host="127.0.0.1", port=port, debug=False)
