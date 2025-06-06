# Getting started

- With Xcode:
  - Open the CLI/Package.swift file
- With Cursor:
  - Open the CLI directory and have the Swift extension installed
- Allow the Swift Packages to download
- From here you should be able to build and run the project using default settings
  - You can manually build the project via `swift build` or `swift build -c release`, the output is placed in the `.build` directory
  - Example manual run: `./.build/release/AppSizeAnalyzer --app-path '/Users/telkins/Downloads/368c569e-7f3d-4aeb-a631-bcf8aa7b251a.zip' --output test.json`

# Linting

This project is configured to use `swift lint`. Each Swift Package has a symlinked configuration file which should work with Xcode. You can also manually run the linter via command line: `swift format --recursive --in-place .`
