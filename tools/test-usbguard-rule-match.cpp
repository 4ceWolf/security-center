// Offline native matching tests: no IPC, daemon, sysfs or device writes.
#include <usbguard/Rule.hpp>
#include <fstream>
#include <iostream>
#include <vector>
#include <stdexcept>
using usbguard::Rule;
static std::string replace(std::string raw,const std::string& old,const std::string& value){
 auto p=raw.find(old);if(p==std::string::npos)throw std::runtime_error("fixture substring absent");raw.replace(p,old.size(),value);return raw;
}
int main(int argc,char**argv){
 try{
  if(argc!=2)return 2;
  std::ifstream input(argv[1]);std::string line,logitech,a4;std::vector<Rule> policy;
  while(std::getline(input,line)){
   if(line.empty()||line[0]=='#')continue;
   if(line.size()>8192||policy.size()>255)return 2;
   policy.push_back(Rule::fromString(line));
   if(line.find("allow id 046d:c542 ")==0)logitech=line;
   if(line.find("allow id 09da:0025 ")==0)a4=line;
  }
  if(logitech.empty()||a4.empty())return 2;
  auto allowed=[&](const std::string& text){const Rule device=Rule::fromString(text);for(const auto& rule:policy)if(rule.appliesTo(device))return rule.getTarget()==Rule::Target::Allow;return false;};
  std::vector<std::pair<std::string,bool>> cases={
   {logitech,true},{a4,true},
   {replace(logitech,"046d:c542","1234:5678"),false},
   {replace(logitech,"via-port \"3-1\"","via-port \"3-2\""),false},
   {replace(logitech,"RE4eSWo4C6sJnh9noxTYUChFLUFP68OpRaakLzFKohg=","AE4eSWo4C6sJnh9noxTYUChFLUFP68OpRaakLzFKohg="),false},
   {replace(a4,"03:01:01 03:01:02","03:01:01 03:01:02 08:06:50"),false},
   {replace(a4,"03:01:01 03:01:02","03:01:02"),false},
   {replace(a4,"serial \"\"","serial \"unexpected\""),false}
  };
  unsigned n=0;for(const auto& test:cases){if(allowed(test.first)!=test.second){std::cerr<<"Native match case failed: "<<n<<'\n';return 1;}++n;}
  std::cout<<"PASS: "<<n<<" native policy matches; exact receivers allowed; wrong ID/port/hash/serial and extra/missing interfaces denied\n";
 }catch(...){std::cerr<<"Native match fixture failed\n";return 1;}
}
