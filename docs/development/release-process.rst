Release Process
***************

Automated Release Process
=========================

HWI uses GitHub Actions to automate the release process. The workflow is defined
in ``.github/workflows/release.yml``.

Creating a Release
------------------

1. Update version numbers in both files:

   - ``pyproject.toml`` - the ``version`` field
   - ``hwilib/__init__.py`` - the ``__version__`` variable

2. Commit the version bump::

    git add pyproject.toml hwilib/__init__.py
    git commit -m "Bump version to X.Y.Z"

3. Create and push a signed tag::

    git tag -s X.Y.Z -m "Release X.Y.Z"
    git push origin X.Y.Z

4. The GitHub Actions workflow will automatically:

   - Validate version consistency
   - Build Linux x86_64 binaries (with GUI)
   - Build Linux ARM64 binaries (without GUI)
   - Build macOS x86_64 Intel binaries (with GUI)
   - Build macOS ARM64 Apple Silicon binaries (without GUI)
   - Build Windows x86_64 binaries (with GUI)
   - Build Python wheel and source distribution
   - Generate SHA256SUMS.txt
   - Create build provenance attestations for all artifacts
   - Create the GitHub release

Alternatively, the workflow can be triggered manually from the GitHub Actions UI
using the "Run workflow" button, which allows specifying a version without creating a tag.


Build Provenance Attestation
============================

HWI uses GitHub Artifact Attestations instead of GPG signing. Attestations provide
cryptographic proof that artifacts were built by the GitHub Actions workflow in this
repository, not by a potentially compromised local environment.

**Benefits over GPG signing:**

- No private keys to manage or protect
- Cryptographically tied to the specific repository, workflow, and commit
- Recorded in Sigstore's public transparency log for auditability
- Verification does not require trusting individual maintainer keys

**How it works:**

1. During the release workflow, GitHub generates an OIDC token proving the build context
2. The ``actions/attest-build-provenance`` action creates a SLSA provenance attestation
3. The attestation is signed using Sigstore and recorded in the Rekor transparency log
4. The attestation links the artifact's SHA256 hash to the repository, workflow, and commit

**GitHub Documentation:**

- `Using artifact attestations to establish provenance for builds <https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds>`_
- `Verifying artifact attestations with the GitHub CLI <https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/verifying-artifact-attestations-with-the-github-cli>`_
- `About artifact attestations <https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/about-artifact-attestations>`_


Verifying Release Artifacts
===========================

HWI uses `immutable releases <https://docs.github.com/en/repositories/releasing-projects-on-github/about-releases#immutable-releases>`_
and `artifact attestations <https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds>`_
to provide cryptographic proof of build provenance.

Install the `GitHub CLI <https://cli.github.com/>`_ if not already installed.

Downloading Release Artifacts
-----------------------------

Download artifacts from the GitHub release page or via CLI::

    # Download a specific asset
    gh release download X.Y.Z --repo bitcoin-core/HWI --pattern 'hwi-*-linux-x86_64.tar.gz'

    # Or download all assets
    gh release download X.Y.Z --repo bitcoin-core/HWI

Immutable Release Verification
------------------------------

Verify release assets were published via immutable release (not manually uploaded)::

    # Verify a specific asset
    gh release verify-asset hwi-X.Y.Z-linux-x86_64.tar.gz --repo bitcoin-core/HWI

    # Verify all downloaded assets
    for f in hwi-X.Y.Z* SHA256SUMS.txt; do gh release verify-asset "$f" --repo bitcoin-core/HWI; done

Immutable releases guarantee that:

- The release was created by an automated workflow, not a human
- Release artifacts cannot be modified or replaced after publication
- The release is permanently linked to the workflow run that created it

Verifying Attestations
----------------------

Verify any downloaded artifact has a valid attestation::

    # Verify a specific artifact
    gh attestation verify hwi-X.Y.Z-linux-x86_64.tar.gz --repo bitcoin-core/HWI

    # Or verify all downloaded assets
    for f in hwi-X.Y.Z* SHA256SUMS.txt; do gh attestation verify "$f" --repo bitcoin-core/HWI; done

Successful verification confirms:

- The artifact was built by the GitHub Actions workflow in this repository
- The specific workflow file and job that produced it
- The git commit SHA the artifact was built from
- The build has not been tampered with since creation

SHA256 Checksums
----------------

Download ``SHA256SUMS.txt`` from the release and verify file integrity::

    sha256sum -c SHA256SUMS.txt


Release Artifacts
=================

Each release includes the following artifacts:

.. list-table::
   :header-rows: 1

   * - Platform
     - Architecture
     - GUI
     - Filename
   * - Linux
     - x86_64
     - Yes
     - ``hwi-X.Y.Z-linux-x86_64.tar.gz``
   * - Linux
     - aarch64
     - No
     - ``hwi-X.Y.Z-linux-aarch64.tar.gz``
   * - macOS
     - x86_64 (Intel)
     - Yes
     - ``hwi-X.Y.Z-mac-x86_64.tar.gz``
   * - macOS
     - arm64 (Apple Silicon)
     - No
     - ``hwi-X.Y.Z-mac-arm64.tar.gz``
   * - Windows
     - x86_64
     - Yes
     - ``hwi-X.Y.Z-windows-x86_64.zip``
   * - Python (any)
     - any
     - Yes
     - ``hwi-X.Y.Z-py3-none-any.whl``
   * - Source
     - any
     - Yes
     - ``hwi-X.Y.Z.tar.gz``

All artifacts are accompanied by ``SHA256SUMS.txt`` containing their checksums.


Deterministic vs Non-Deterministic Builds
=========================================

**Deterministic (reproducible) builds** means that given the same source code, build
environment, and instructions, you get byte-for-byte identical output every time,
regardless of when or where you build it.

Why Determinism Matters
-----------------------

For security-critical software like HWI (which handles cryptocurrency transaction signing),
deterministic builds provide important guarantees:

- **Verification**: Anyone can rebuild from source and verify the binary matches the release
- **Trust**: Users don't have to trust that the build machine wasn't compromised
- **Auditability**: If binaries differ unexpectedly, something changed (malicious or otherwise)

Factors That Break Determinism
------------------------------

Several factors cause binary output to vary between builds:

- **Timestamps**: Compilers and tools embed build time into binaries
- **File ordering**: Filesystems may return files in different orders during builds
- **Memory addresses**: ASLR and pointer values can leak into output
- **Absolute paths**: Build paths like ``/home/alice/project`` get embedded in debug info
- **Python bytecode**: Hash randomization changes ``.pyc`` file contents
- **Toolchain versions**: Different compiler versions produce different machine code

How HWI Achieves Determinism (Linux/Windows)
--------------------------------------------

The Linux and Windows builds use Docker containers with several techniques to ensure
reproducibility:

**Fixed timestamps**::

    # Set all Python source files to a fixed date
    TZ=UTC find ${lib_dir} -name '*.py' -type f -execdir touch -t "201901010000.00" '{}' \;

**Fixed Python hash seed**::

    export PYTHONHASHSEED=42

**Patched Python build with fixed date**::

    BUILD_DATE="Jan  1 2019" BUILD_TIME="00:00:00" pyenv install ...

**Containerized environment**: Docker ensures identical toolchain versions and paths.

Why macOS Builds Are Non-Deterministic
--------------------------------------

macOS builds cannot achieve full determinism for several reasons:

- **No Docker on macOS**: Cannot use the same containerized environment as Linux
- **Xcode/system libraries**: Apple's toolchain embeds UUIDs and timestamps into binaries
- **Code signing**: macOS binaries receive ad-hoc signatures containing timestamps
- **Homebrew variations**: Library versions may differ between build machines
- **System frameworks**: macOS links against system frameworks that vary by OS version

Mitigating Non-Determinism with Attestation
-------------------------------------------

Since macOS builds cannot be deterministic, we use **build provenance attestation** as
an alternative trust mechanism. Instead of "anyone can reproduce this exact binary,"
attestation provides "GitHub cryptographically attests this binary came from our CI pipeline."

Attestation proves:

- The binary was built by GitHub Actions (not a potentially compromised local machine)
- From a specific commit in this repository
- Using the exact workflow file at that commit
- The binary has not been modified since the build completed

This is a different but valid trust model. Users trust GitHub's infrastructure and the
transparency log rather than relying on reproducibility for verification.

For more information, see the `Build Provenance Attestation`_ section above.


Manual Build Process
====================

The following documents the manual build process using Docker containers. This is
useful for:

- Local development and testing
- Reproducing builds for verification
- Building releases if CI is unavailable

Note: The automated GitHub Actions workflow is the preferred method for official releases.

Deterministic builds with Docker
--------------------------------

Create the docker images::

    docker build --no-cache -t hwi-builder -f contrib/build.Dockerfile .
    docker build --no-cache -t hwi-wine-builder -f contrib/build-wine.Dockerfile .

    # arm64
    sudo apt-get install qemu-user-static
    docker buildx build --no-cache --platform linux/arm64 -t hwi-builder-arm64 -f contrib/build.Dockerfile .

Build everything::

    docker run -it --name hwi-builder -v $PWD:/opt/hwi --rm  --workdir /opt/hwi hwi-builder /bin/bash -c "contrib/build_bin.sh && contrib/build_dist.sh"
    docker run -it --name hwi-wine-builder -v $PWD:/opt/hwi --rm  --workdir /opt/hwi hwi-wine-builder /bin/bash -c "contrib/build_wine.sh"
    docker run --platform linux/arm64 -it --rm --name hwi-builder-arm64 -v $PWD:/opt/hwi --workdir /opt/hwi hwi-builder-arm64 /bin/bash -c "contrib/build_bin.sh --without-gui && contrib/build_dist.sh --without-gui"

Building macOS binary
---------------------

Note that the macOS build is non-deterministic.

First install `pyenv <https://github.com/pyenv/pyenv>`_ using whichever method you prefer.

Then a deterministic build of Python 3.9.19 needs to be installed. This can be done with the patch in ``contrib/reproducible-python.diff``. First ``cd`` into HWI's source tree. Then use::

    cat contrib/reproducible-python.diff | PYTHON_CONFIGURE_OPTS="--enable-framework" BUILD_DATE="Jan  1 2019" BUILD_TIME="00:00:00" pyenv install -kp 3.9.19

Make sure that python 3.9.19 is active::

    $ python --version
    Python 3.9.19

Now install `Poetry <https://github.com/sdispater/poetry>`_ with ``pip install poetry``

Additional dependencies can be installed with::

    brew install libusb

Build the binaries by using ``contrib/build_bin.sh``.
