// Unprivileged syntax check using the installed native USBGuard parser only.
// Never contacts the daemon or changes device authorization.
#include <usbguard/Rule.hpp>
#include <iostream>
#include <string>
int main() {
  std::string line;
  unsigned count=0;
  try {
    while (std::getline(std::cin,line)) {
      if(line.size()>8192 || ++count>256) return 2;
      if(line.empty() || line[0]=='#') continue;
      auto rule=usbguard::Rule::fromString(line);
      std::cout << rule.toString() << '\n';
    }
    if(!std::cin.eof()) return 2;
  } catch(...) { std::cerr << "USBGuard rule syntax rejected\n"; return 1; }
  return 0;
}
