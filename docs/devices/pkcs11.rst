PKCS#11 Token
=============

The PKCS#11 Token device implementation allows HWI to interact with PKCS#11-compliant Hardware Security Modules (HSMs) that support the secp256k1 curve.

Requirements
------------

- A PKCS#11-compliant HSM with secp256k1 curve support.
- The PKCS#11 library for your HSM.
- The ``python-pkcs11`` Python package.

Windows-specific Requirements
-----------------------------

On Windows, you'll need:

1.  **Visual Studio Build Tools with C++ support**
    - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
    - Select "Desktop development with C++".
    - Make sure to include the Windows 10 SDK.

2.  **OpenSSL development headers**
    - Download from: https://slproweb.com/products/Win32OpenSSL.html
    - Choose the "Win64 OpenSSL" version.
    - Ensure the OpenSSL bin directory is on PATH.

3.  **The PKCS#11 library for your HSM** (usually a ``.dll`` file)
    - Prefer specifying its absolute path via ``PKCS11_LIB_PATH`` or placing it alongside the application.
    - Avoid copying into ``C:\Windows\System32`` to reduce DLL hijacking risks.

Installation Steps for Windows:

1.  Install the prerequisites in the order listed above.
2.  Install ``python-pkcs11``:

    .. code-block:: shell

       pip install python-pkcs11

    If you get a "Failed building wheel" error, ensure prerequisites are installed correctly and try running the command in a new terminal.

Configuration
-------------

The device can be configured using environment variables. Command-line flags will override these variables if provided.

- ``PKCS11_LIB_PATH``: **(Required)** Path to the PKCS#11 library.
- ``PKCS11_TOKEN_LABEL``: Label of the token to use (default: "Bitcoin").
- ``PKCS11_PIN``: User PIN for token login. For security, it is better to rely on the interactive prompt than to set this variable.

Example environment variable setup:

.. code-block:: powershell

   # On Windows (PowerShell)
   $env:PKCS11_LIB_PATH = "C:\path\to\your\pkcs11\library.dll"
   $env:PKCS11_TOKEN_LABEL = "YourTokenLabel"

.. code-block:: shell

   # On Linux/macOS
   export PKCS11_LIB_PATH=/path/to/your/pkcs11/library.so
   export PKCS11_TOKEN_LABEL=YourTokenLabel

Usage
-----

1.  **Initialize your HSM** with a master key labeled ``MASTER_KEY`` using the secp256k1 curve.
2.  **Use HWI** with your PKCS#11 token:

    .. code-block:: shell

       # List available devices
       hwi enumerate

       # Get the master public key
       hwi --device-type pkcs11 --path /path/to/library.so getmasterxpub

Security Considerations
-----------------------

- The PKCS#11 token must be properly configured with appropriate access controls.
- The master key should be protected with a strong PIN/password.
- The PKCS#11 library should be from a trusted source.
- The token should be physically secured.

Limitations
-----------

- Only supports the secp256k1 curve.
- Requires the token to be pre-initialized with a master key.
- May not support all HWI features depending on the token's capabilities.

Troubleshooting
---------------

- Verify your PKCS#11 library is properly installed and the path is correct.
- Check that your token supports the secp256k1 curve.
- Ensure the ``MASTER_KEY`` exists and is accessible.
- Check the token's logs for any error messages.