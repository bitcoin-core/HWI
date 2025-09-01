PKCS#11 Token
=============

The PKCS#11 Token device implementation allows HWI to interact with PKCS#11-compliant Hardware Security Modules (HSMs) that support the secp256k1 curve.

Requirements
------------

- A PKCS#11-compliant HSM with secp256k1 curve support
- The PKCS#11 library for your HSM
- The ``python-pkcs11`` Python package

Windows-specific Requirements
---------------------------

On Windows, you'll need:

1. Visual Studio Build Tools with C++ support
   - Download from: https://visualstudio.microsoft.com/visual-cpp-build-tools/
   - Select "Desktop development with C++"
   - Make sure to include the Windows 10 SDK

2. OpenSSL development headers
   - Download from: https://slproweb.com/products/Win32OpenSSL.html
   - Choose the "Win64 OpenSSL" version
   - During installation, select "Copy OpenSSL DLLs to Windows system directory"

3. The PKCS#11 library for your HSM (usually a .dll file)
   - Place the .dll file in a system path (e.g., C:\Windows\System32)
   - Or specify its path using the PKCS11_LIB_PATH environment variable

Installation Steps for Windows:

1. Install the prerequisites in the order listed above

2. Install python-pkcs11:
   .. code-block:: powershell
      pip install python-pkcs11
   If you get a "Failed building wheel" error:
   - Make sure Visual Studio Build Tools are installed
   - Ensure OpenSSL is installed and in your PATH
   - Try running the command in a new terminal after installing the prerequisites

Configuration
------------

The following environment variables can be used to configure the PKCS#11 device:

- ``PKCS11_LIB_PATH``: Path to the PKCS#11 library (required)
- ``PKCS11_TOKEN_LABEL``: Label of the token to use (default: "Bitcoin")

Usage
-----

1. Set up your environment variables:

   .. code-block:: powershell
      # On Windows (PowerShell):
      $env:PKCS11_LIB_PATH = "C:\path\to\your\pkcs11\library.dll"
      $env:PKCS11_TOKEN_LABEL = "YourTokenLabel"
      # On Linux/macOS:
      export PKCS11_LIB_PATH=/path/to/your/pkcs11/library.so
      export PKCS11_TOKEN_LABEL=YourTokenLabel
2. Initialize your HSM with a master key:

   - Create a master key with label "MASTER_KEY"
   - Ensure the key uses the secp256k1 curve
   - Set appropriate access controls

3. Use HWI with your PKCS#11 token:

   .. code-block:: bash
      hwi enumerate  # List available devices
      hwi --device-type pkcs11 --path /path/to/library.so getmasterxpub
Security Considerations
---------------------

- The PKCS#11 token must be properly configured with appropriate access controls
- The master key should be protected with a strong PIN/password
- The PKCS#11 library should be from a trusted source
- The token should be physically secured

Limitations
----------

- Only supports secp256k1 curve
- Requires the token to be pre-initialized with a master key
- May not support all HWI features depending on the token's capabilities

Troubleshooting
--------------

If you encounter issues:

1. Verify your PKCS#11 library is properly installed
2. Check that your token supports the secp256k1 curve
3. Ensure the master key exists and is accessible
4. Check the token's logs for any error messages
5. Verify the environment variables are set correctly

Windows-specific Troubleshooting:

1. If you get a "Failed building wheel" error:
   - Make sure Visual Studio Build Tools are installed
   - Ensure OpenSSL is installed and in your PATH
   - Try running the command in a new terminal after installing the prerequisites

2. If the library is not found:
   - Check if the .dll file is in a system path
   - Verify the PKCS11_LIB_PATH environment variable is set correctly
   - Try running as Administrator

3. If you get a "DLL load failed" error:
   - Check if all required dependencies are installed
   - Verify the architecture matches (32-bit vs 64-bit)
   - Try installing the Visual C++ Redistributable
   - Make sure OpenSSL DLLs are in your system PATH 