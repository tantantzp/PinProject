#include <string>
#include <map>
#include <set>

/*!
 * A container which holds an instruction disassembly for a sparse collection of
 * interesting instructions.
 */
class INS_CONTAINER
{
  static const int __lockresult = 2012;
  typedef std::map<ADDRINT, int> INS_MAP;
  public:
    INS_CONTAINER() { InitLock(&_lock);}
    int RegisterInsID(INS ins){
    	int resultid = 0;
        GetLock(&_lock, __lockresult);
        
        ADDRINT addr = INS_Address(ins);
        INS_MAP::iterator i = _map.find(addr);
        if(i == _map.end()){
        	// new, add to the map
        	_addresses.push_back(addr);
        	// _names.push_back(dis);
        	resultid = _addresses.size();
        	_map.insert(make_pair(addr, resultid));
        }else
        	// existing
        	resultid = i->second;

        ReleaseLock(&_lock);
        return resultid;
    }

	ADDRINT GetAddrByID(int id)	{ return _addresses[id-1];}
  private:
    PIN_LOCK _lock;
    INS_MAP               _map;
    std::vector<ADDRINT>  _addresses;
};

class BBL_CONTAINER
{
  static const int __lockresult = 2012;
  typedef std::map<std::pair<ADDRINT,USIZE>, int> BBL_MAP;
  public:
    BBL_CONTAINER() { InitLock(&_lock);}
    int RegisterBblID(BBL bbl){
    	int resultid = 0;
        GetLock(&_lock, __lockresult);
        
        // Use the address *and* size of BBL to make sure it's unique
        ADDRINT addr = BBL_Address(bbl);
        USIZE   size = BBL_Size(bbl);
        std::pair<ADDRINT,USIZE> pair(addr, size);

        BBL_MAP::iterator i = _map.find(pair);
        if(i == _map.end()){
        	// new, add to the map
        	_addresses.push_back(addr);
        	// _names.push_back(dis);
        	resultid = _addresses.size();
        	_map.insert(make_pair(pair, resultid));
        }else
        	// existing
        	resultid = i->second;

        ReleaseLock(&_lock);
        return resultid;
    }

    ADDRINT GetAddrByID(int id)	{ return _addresses[id-1];}
  private:
    PIN_LOCK _lock;
    BBL_MAP               _map;
    std::vector<ADDRINT>  _addresses;
};
