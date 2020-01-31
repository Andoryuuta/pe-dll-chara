# pe-dll-chara
Small CLI tool for changing a PE's [DLL Characteristics](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#dll-characteristics).

General idea taken from [Didier Stevens' `setdllcharacteristics` tool](https://blog.didierstevens.com/2010/10/17/setdllcharacteristics/).

## Setup
```
git clone https://github.com/Andoryuuta/pe-dll-chara.git
cd pe-dll-chara
pip3 install -r requirements.txt
```

## Usage
Turning off ALSR:
```
python3 pe-dll-chara.py something.exe DYNAMIC_BASE=false
```

Turning off ALSR _and_ DEP:
```
python3 pe-dll-chara.py something.exe DYNAMIC_BASE=false NX_COMPAT=false
```

Print the current flags:
```
python3 pe-dll-chara.py something.exe
```
