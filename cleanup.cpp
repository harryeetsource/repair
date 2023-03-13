#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int main() {
    // Perform full cleanup and system file check
    std::cout << "Performing full cleanup and system file check." << std::endl;
    system("dism /online /cleanup-image /startcomponentcleanup");
    system("dism /online /cleanup-image /restorehealth");
    system("sfc /scannow");

    // Perform additional cleanup steps
    std::cout << "Performing additional cleanup steps." << std::endl;
    system("cleanmgr /sagerun:1");
    system("del /q /s %temp%\\*");
    system("dism /online /cleanup-image /startcomponentcleanup /resetbase");
    system("pnputil /e");
    std::cout << "Enter driver package name to delete or press Enter to skip: ";
    std::string input;
    std::getline(std::cin, input);
    if (!input.empty()) {
        std::string command = "pnputil /d " + input;
        system(command.c_str());
    }

    // Wait for user input before exiting
    std::cout << "Cleanup complete. Press Enter to exit." << std::endl;
    std::cin.ignore();

    return 0;
}
