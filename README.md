# Keycloak Project

This project provides an implementation for setting up Keycloak with Python and managing the routes the user can access to through the Flask app.

# Requirements

Remember to start your Keycloak server, create the client, users and roles as needed.

## Installation

Clone the repository:

```bash
git clone https://github.com/angelteyul/keycloak-flask.git
```

Install `venv` and create a virtual environment:

```bash
python -m pip install virtualenv

python -m venv [virtual_env_name]
```

Start the virtual environment:

```bash
# linux/mac
source [virtual_env_name]/bin/activate

# windows
[virtual_env_name]/Scripts/activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Getting Started

Remember to create a `.env` file based on the `.env.example` file by replacing and adding your Keycloak server details.

To start the project, run the `auth.py` file:

```bash
python auth.py
```

This file implements the `python-keycloak` package to provide access to the Keycloak API.

## Alternative version

The `decoded_token.py` file contains a test using another method to set up Keycloak and get user roles by decoding the user's token.

You can run it with:

```bash
python decoded_token.py
```
