#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>

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

std::vector<std::string> getDriverPackages() {
    std::vector<std::string> driverPackages;
    std::string output = exec("pnputil /e");
    size_t start = output.find("Published name : ") + 18;
    while (start != std::string::npos) {
        size_t end = output.find('\n', start);
        std::string packageName = output.substr(start, end - start);
        driverPackages.push_back(packageName);
        start = output.find("Published name : ", end) + 18;
    }
    return driverPackages;
}

std::vector<std::string> getWMICApps() {
    std::vector<std::string> wmicApps;
    std::string output = exec("wmic product get name,identifyingnumber");
    size_t start = output.find('\n') + 1;
    while (start != std::string::npos) {
        size_t end = output.find('\n', start);
        std::string line = output.substr(start, end - start);
        size_t delimiter = line.find("  ");
        if (delimiter != std::string::npos) {
            std::string appName = line.substr(0, delimiter);
            std::string appId = line.substr(delimiter);
            wmicApps.push_back(appName + " - " + appId);
        }
        start = output.find('\n', end) + 1;
    }
    return wmicApps;
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

    // Delete driver package
    std::vector<std::string> driverPackages = getDriverPackages();
    if (!driverPackages.empty()) {
        std::cout << "Driver packages found: " << std::endl;
        for (int i = 0; i < driverPackages.size(); i++) {
            std::cout << i + 1 << ". " << driverPackages[i] << std::endl;
        }
        std::cout << "Enter the number of the driver package to delete or press Enter to skip: ";
        std::string input;
        std::getline(std::cin, input);
        if (!input.empty()) {
            int index = std::stoi(input) - 1;
            if (index >= 0 && index < driverPackages.size()) {
                std::string command = "pnputil /d \"" + driverPackages[index] + "\"";

system(command.c_str());
} else {
std::cout << "Invalid input. Skipping driver package deletion." << std::endl;
}
}
} else {
std::cout << "No driver packages found. Skipping driver package deletion." << std::endl;
}
// Delete Windows Installer application
std::vector<std::string> wmicApps = getWMICApps();
if (!wmicApps.empty()) {
    std::cout << "WMIC applications found: " << std::endl;
    for (int i = 0; i < wmicApps.size(); i++) {
        std::cout << i + 1 << ". " << wmicApps[i] << std::endl;
    }
    std::cout << "Enter the number of the WMIC application to uninstall or press Enter to skip: ";
    std::string input;
    std::getline(std::cin, input);
    if (!input.empty()) {
        int index = std::stoi(input) - 1;
        if (index >= 0 && index < wmicApps.size()) {
            std::string appId = wmicApps[index].substr(wmicApps[index].find(" - ") + 3);
            std::string command = "wmic product where \"IdentifyingNumber='" + appId + "'\" call uninstall";
            system(command.c_str());
        } else {
            std::cout << "Invalid input. Skipping WMIC application uninstallation." << std::endl;
        }
    }
} else {
    std::cout << "No WMIC applications found. Skipping WMIC application uninstallation." << std::endl;
}

// Disable Windows Media Player feature
system("dism /online /disable-feature /featurename:WindowsMediaPlayer");
system("vssadmin delete shadows /for=C: /oldest");
system("forfiles /p \"C:\\Windows\\Logs\" /s /m *.log /d -7 /c \"cmd /c del @path\"");

// Wait for user input before exiting
std::cout << "Cleanup complete. Press Enter to exit." << std::endl;
std::cin.ignore();
return 0;
}
