#pragma once
#include <stdio.h>
#include <windows.h>
#include <tchar.h>
#include "accctrl.h"
#include "aclapi.h"
#pragma comment(lib, "advapi32.lib")


int PrintOwner();
int PrintDAcl();
void  ACLToNewFileOrDirectory();
void tmp();