# Project notes

- Builds run on GitHub Actions (`.github/workflows/build.yml`); do not run Gradle locally — the user's device is too weak.
- `android-actions/setup-android@v3` must be configured with `packages: platform-tools`; its default `tools` package is retired and makes `sdkmanager` exit 1.
