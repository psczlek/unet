# UNET (The Unified Network Toolkit) (dev)

## Platforms

unet has been ran on the following platforms:
- ubuntu 22.04
- ubuntu 24.04
- kali linux
- macOS 14
- macOS 15

## Installation

*This project works with Python 3.12+ on macOS and Linux.*

### Step 1: (Optional) Set up a Virtual Environment

To keep the project dependencies isolated from your global Python environment,
it is recommended to create a Python virtual environment.

1. Create a virtual environment (replace `<path to virtualenv>` with the desired path):
    ```bash
    python3 -m venv <path to virtualenv>
    ```

2. Activate the virtual environment:
    ```bash
    source <path to virtualenv>/bin/activate
    ```

---

### Step 2: Install Required Dependencies

1. Install the necessary dependencies:
    ```bash
    python3 -m pip install -r requirements.txt
    ```

2. *(Optional)* If you are developing the project, install additional
development tools for testing, linting, and type checking:
    ```bash
    python3 -m pip install -r requirements_dev.txt
    ```

---

### Step 3: Install the Project

- To install the project, run the following command:
    ```bash
    python3 -m pip install .
    ```

---

### Step 4: (For Developers) Editable Install

If you're a developer and want to make changes to the project while testing them
immediately, you can install the project in "editable" mode. This allows you to
make changes without needing to reinstall each time.

- Run the following command:
    ```bash
    python3 -m pip install -e .
    ```

This links the project directory directly into the environment, so changes are
reflected in real time.

---

### Step 5: (Linux Only) Running the Tool with Root Privileges

On Linux, the tool might require root privileges to operate, especially since it
interacts with raw sockets.

If the project has been installed within a virtual environment, you can run it
as follows:

```bash
sudo "<path to python's executable in the virtualenv where the project is installed>" -m unet
```

For example:

```bash
sudo /home/user/.virtualenvs/unet/bin/python -m unet
```

This ensures that the correct Python interpreter from the virtual environment is
used while running the tool with elevated privileges.

---

If everything went well, it should display the usage message. If you encountered
an error during installation or on the first run after installation, please
report it.

---

### NOTE

On the first run, unet will create a configuration directory at `~/.config/unet`,
where it will store its config file, directories for external modules, and the
history file.

## License

This project is released under the BSD 3-Clause license.
See [LICENSE](https://github.com/psczlek/unet/blob/dev/LICENSE) for
more information

## Bugs

I know that the dev version might contain weird bugs, inaccuraties or missing
implementations.
