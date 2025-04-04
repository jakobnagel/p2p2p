To run the code, first create a venv with:
python3 virtualenv virtualenv

Then activate the venv with:
source venv/bin/activate

Once the venv is active, download the requirements with:
pip3 install -r requirements.txt

Finally run the code in two terminals with the following two commands:
python3 client.py
python3 server.py

To retire keys, while the program is not running execute:
rm keys/*
Contacts will be notified when the peer is back online.

To run the tests, run the following command in the 'python' directory:
python3 -m pytest -s tests
