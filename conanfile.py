from conan import ConanFile
from conan.errors import ConanInvalidConfiguration


class MySnifferRecipe(ConanFile):
    name = "my_sniffer"
    version = "0.1.0"
    package_type = "application"

    settings = "os", "arch", "compiler", "build_type"

    requires = "gtest/1.14.0"

    generators = "CMakeDeps", "CMakeToolchain"

    def layout(self):
        self.folders.generators = "."

    def validate(self):
        if self.settings.os not in ("Windows", "Linux"):
            raise ConanInvalidConfiguration(
                "Ce projet supporte uniquement Windows et Linux"
            )