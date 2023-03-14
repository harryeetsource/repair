#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>
#include <sstream>

std::string exec(const char * cmd) {
  std::array < char, 128 > buffer;
  std::string result;
  std::unique_ptr < FILE, decltype( & pclose) > pipe(popen(cmd, "r"), pclose);
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    result += buffer.data();
  }
  return result;
}

std::vector < std::string > getDriverPackages() {
  std::vector < std::string > driverPackages;
  std::istringstream input(exec("pnputil /e"));
  std::string line;
  while (std::getline(input, line)) {
    if (line.find("Published name : ") != std::string::npos) {
      std::string packageName = line.substr(18);
      driverPackages.push_back(packageName);
    }
  }
  return driverPackages;
}

std::vector < std::string > getWMICApps() {
  std::vector < std::string > wmicApps;
  std::istringstream input(exec("wmic product get name,identifyingnumber"));
  std::string line;
  std::getline(input, line);
  while (std::getline(input, line)) {
    size_t delimiter = line.find("  ");
    if (delimiter != std::string::npos) {
      std::string appName = line.substr(0, delimiter);
      std::string appId = line.substr(delimiter);
      wmicApps.push_back(appName + " - " + appId);
    }
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
  {
    std::vector < std::string > driverPackages;
    std::istringstream input(exec("pnputil /e"));
    std::string line;
    while (std::getline(input, line)) {
      if (line.find("Published name : ") != std::string::npos) {
        std::string packageName = line.substr(18);
        driverPackages.push_back(packageName);
      }
    }
    if (!driverPackages.empty()) {
      std::cout << "Driver packages found: " << std::endl;
      for (int i = 0; i < driverPackages.size(); i++) {
        std::cout << i + 1 << ". " << driverPackages[i] << std::endl;
      }
      
      // Modified driver package deletion section
      int index = -1;
      while (true) {
          std::cout << "Enter the number of the driver package to delete or press Enter to skip: ";
          std::string input;
          std::getline(std::cin, input);
          if (input.empty()) {
              break;
          }
          index = std::stoi(input) - 1;
if (index >= 0 && index < driverPackages.size()) {
std::string command = "pnputil /d \"" + driverPackages[index] + "\"";

// Execute the command to delete the selected driver package
std::cout << "Deleting driver package: " << driverPackages[index] << std::endl;
system(command.c_str());
} else {
std::cout << "Invalid selection. Please try again." << std::endl;
}
}
} else {
std::cout << "No driver packages found. Skipping driver package deletion." << std::endl;
}
}

// Uninstall WMIC app
{
std::vector<std::string> wmicApps = getWMICApps();
if (!wmicApps.empty()) {
std::cout << "WMIC apps found: " << std::endl;
for (int i = 0; i < wmicApps.size(); i++) {
std::cout << i + 1 << ". " << wmicApps[i] << std::endl;
}
  // Modified WMIC app uninstallation section
  int index = -1;
  while (true) {
    std::cout << "Enter the number of the WMIC app to uninstall or press Enter to skip: ";
    std::string input;
    std::getline(std::cin, input);
    if (input.empty()) {
      break;
    }
    index = std::stoi(input) - 1;
    if (index >= 0 && index < wmicApps.size()) {
      std::string appId = wmicApps[index].substr(wmicApps[index].find("-") + 2);
      std::string command = "msiexec /x " + appId;
      // Execute the command to uninstall the selected WMIC app
      std::cout << "Uninstalling WMIC app: " << wmicApps[index] << std::endl;
      system(command.c_str());
    } else {
      std::cout << "Invalid selection. Please try again." << std::endl;
    }
  }
} else {
  std::cout << "No WMIC apps found. Skipping WMIC app uninstallation." << std::endl;
}
}

// Disable Windows Media Player feature
system("dism /online /disable-feature /featurename:WindowsMediaPlayer");
system("vssadmin delete shadows /for=C: /oldest");
system("forfiles /p \"C:\\Windows\\Logs\" /s /m *.log /d -7 /c \"cmd /c del @path\"");


std::cout << "Cleanup complete. Press Enter to exit." << std::endl;
std::cin.ignore();
return 0;
}
